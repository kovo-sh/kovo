process.env.KOVO_ALLOW_LOCAL_LAB ??= '1'
/**
 * Typed proof compilers: each compiler emits an identifier-bound, proof-strength-compliant replay
 * spec that the ReplayVerifier confirms on a vulnerable fixture and rejects on a hardened one.
 * Validation errors, determinism and the LLM tool schema are covered too.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { test } from 'node:test'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import { classifyHttpChainAssertion, verifyReplaySpec } from '../src/server/replay-verifier.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import {
  ProofCompileError,
  describeProofTools,
  proofToolNames,
  proveAuthzReadDiff,
  proveBusinessInvariant,
  proveCanaryOrRedirect,
  proveStateMutationDiff,
  validateProofInput,
} from '../src/server/proof-tools.ts'
import type { CompiledProof } from '../src/server/proof-tools.ts'

// ---------------------------------------------------------------------------
// Fixture + verifier harness
// ---------------------------------------------------------------------------

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
    headerName: 'X-Persona', secret: `tok-${handle}`, canaryMarkers: [],
  }
}

function grantFor(origins: string[], personas = ['owner', 'attacker', 'member']): Grant {
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

async function verify(compiled: CompiledProof, grant: Grant) {
  const parsed = declarativeReplaySpecSchema.safeParse(compiled.spec)
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues))
  return verifyReplaySpec({
    spec: compiled.spec,
    broker: new RequestBroker({ rejectUnauthorized: false }),
    backend: new LocalJqBackend(),
    grant,
    signal: AbortSignal.timeout(20_000),
  })
}

function assertIdentifierBound(compiled: CompiledProof): void {
  assert.notEqual(classifyHttpChainAssertion(compiled.assertionsJq), 'status_only', compiled.assertionsJq)
  assert.match(compiled.assertionsJq, /\.steps\.[a-z0-9_-]+\.(?:json\.[A-Za-z_]|body|headers\.location)/)
  assert.doesNotMatch(compiled.assertionsJq, /confirmed:\s*\(?\s*\.steps\.[a-z0-9_-]+\.status\s*==/)
}

// ---------------------------------------------------------------------------
// 1. Authorization read differential
// ---------------------------------------------------------------------------

function ordersFixture(hardened: boolean) {
  return fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname !== '/api/orders/42') return json(res, 404, { error: 'not_found' })
    const actor = String(req.headers['x-persona'] ?? '').replace(/^tok-/, '')
    if (!actor) return json(res, 401, { error: 'unauthorized' })
    if (hardened && actor !== 'owner') return json(res, 403, { error: 'forbidden' })
    return json(res, 200, { id: 42, owner: 'owner', privateNote: 'OWNER-ONLY-v5-proof' })
  })
}

function authzProof(origin: string): CompiledProof {
  return proveAuthzReadDiff({
    origin,
    ownerPersona: 'owner',
    attackerPersona: 'attacker',
    endpoint: '/api/orders/{resourceId}',
    method: 'GET',
    resourceId: '42',
    identifierPath: 'id',
  })
}

test('prove_authz_read_diff: vulnerable cross-actor read confirms, hardened denial dismisses', async () => {
  const vuln = await ordersFixture(false)
  try {
    const compiled = authzProof(vuln.origin)
    assertIdentifierBound(compiled)
    assert.equal(compiled.spaCatchallControl, true)
    assert.match(compiled.spec.steps[1]!.request.pathAndQuery, /\/api\/orders\/42$/)
    const res = await verify(compiled, grantFor([vuln.origin]))
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
    const proof = res.evidencePayload.proofStrength as { satisfied?: boolean; differential?: string }
    assert.equal(proof.satisfied, true)
    assert.equal(proof.differential, 'cross_actor_access')
  } finally { await vuln.close() }

  const hardened = await ordersFixture(true)
  try {
    const res = await verify(authzProof(hardened.origin), grantFor([hardened.origin]))
    assert.equal(res.verdict, 'dismissed', String(res.outcome.reason))
    assert.equal(res.outcome.confirmed, false)
  } finally { await hardened.close() }
})

// ---------------------------------------------------------------------------
// 2. State mutation differential
// ---------------------------------------------------------------------------

function accountFixture(hardened: boolean) {
  let role = 'user'
  return fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname !== '/api/accounts/7') return json(res, 404, { error: 'not_found' })
    if (req.method === 'GET') return json(res, 200, { id: 7, role })
    if (req.method !== 'PATCH') return json(res, 405, { error: 'method_not_allowed' })
    const actor = String(req.headers['x-persona'] ?? '').replace(/^tok-/, '')
    if (hardened && actor !== 'owner') return json(res, 403, { error: 'forbidden' })
    role = 'admin'
    return json(res, 200, { ok: true })
  })
}

function stateProof(origin: string): CompiledProof {
  return proveStateMutationDiff({
    origin,
    beforeRead: { method: 'GET', pathAndQuery: '/api/accounts/7', persona: 'member' },
    probeMutation: { method: 'PATCH', pathAndQuery: '/api/accounts/7', persona: 'attacker', jsonBody: { role: 'admin' } },
    afterRead: { method: 'GET', pathAndQuery: '/api/accounts/7', persona: 'member' },
    changedFieldPath: 'role',
    op: 'changed',
  })
}

test('prove_state_mutation_diff: persisted field delta confirms, hardened no-op dismisses', async () => {
  const vuln = await accountFixture(false)
  try {
    const compiled = stateProof(vuln.origin)
    assertIdentifierBound(compiled)
    assert.deepEqual(compiled.warnings, ['No benign control mutation supplied; the control arm is the pre-mutation read, so only the before/after field delta is asserted.'])
    const res = await verify(compiled, grantFor([vuln.origin]))
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
    const proof = res.evidencePayload.proofStrength as { differential?: string }
    assert.equal(proof.differential, 'state_delta')
  } finally { await vuln.close() }

  const hardened = await accountFixture(true)
  try {
    const res = await verify(stateProof(hardened.origin), grantFor([hardened.origin]))
    assert.equal(res.verdict, 'dismissed', String(res.outcome.reason))
    assert.equal(res.outcome.confirmed, false)
  } finally { await hardened.close() }
})

// ---------------------------------------------------------------------------
// 3. Business invariant
// ---------------------------------------------------------------------------

function transferFixture(hardened: boolean) {
  let balance = 100
  return fixture(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/balance' && req.method === 'GET') return json(res, 200, { balance })
    if (url.pathname !== '/api/transfer' || req.method !== 'POST') return json(res, 404, { error: 'not_found' })
    const chunks: Buffer[] = []
    for await (const chunk of req) chunks.push(Buffer.from(chunk))
    const amount = Number(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}').amount)
    if (!Number.isFinite(amount)) return json(res, 400, { error: 'bad_request' })
    if (hardened && amount > balance) return json(res, 400, { error: 'insufficient_funds' })
    balance -= amount
    return json(res, 200, { ok: true })
  })
}

function invariantProof(origin: string): CompiledProof {
  return proveBusinessInvariant({
    origin,
    controlFlow: [{ method: 'POST', pathAndQuery: '/api/transfer', persona: 'member', jsonBody: { amount: 50 } }],
    probeFlow: [{ method: 'POST', pathAndQuery: '/api/transfer', persona: 'member', jsonBody: { amount: 150 } }],
    readback: { method: 'GET', pathAndQuery: '/api/balance', persona: 'member' },
    fieldPath: 'balance',
    op: 'gte',
    baselineRef: 0,
  })
}

test('prove_business_invariant: negative balance violates the invariant; hardened clamp dismisses', async () => {
  const vuln = await transferFixture(false)
  try {
    const compiled = invariantProof(vuln.origin)
    assertIdentifierBound(compiled)
    assert.deepEqual(compiled.spec.steps.map(step => [step.id, step.role]), [
      ['control_flow_1', 'control'], ['control_readback', 'control'],
      ['probe_flow_1', 'probe'], ['probe_readback', 'probe'],
    ])
    const res = await verify(compiled, grantFor([vuln.origin]))
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
  } finally { await vuln.close() }

  const hardened = await transferFixture(true)
  try {
    const res = await verify(invariantProof(hardened.origin), grantFor([hardened.origin]))
    assert.equal(res.verdict, 'dismissed', String(res.outcome.reason))
    assert.equal(res.outcome.confirmed, false)
  } finally { await hardened.close() }
})

// ---------------------------------------------------------------------------
// 4a. Stored marker propagation
// ---------------------------------------------------------------------------

const storedMarker = 'kovo-marker-7f3a9c'

function commentsFixture(hardened: boolean) {
  let stored = ''
  return fixture(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/comments' && req.method === 'POST') {
      const chunks: Buffer[] = []
      for await (const chunk of req) chunks.push(Buffer.from(chunk))
      stored = String(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}').text ?? '')
      return json(res, 201, { ok: true })
    }
    if (url.pathname === '/page' && req.method === 'GET') {
      return html(res, 200, `<html><body><div id="comments">${hardened ? 'no comments' : stored}</div></body></html>`)
    }
    return html(res, 404, 'not found')
  })
}

function storedXssProof(origin: string): CompiledProof {
  return proveCanaryOrRedirect({
    origin,
    plantStep: { method: 'POST', pathAndQuery: '/comments', persona: 'member', jsonBody: { text: storedMarker } },
    triggerStep: { method: 'GET', pathAndQuery: '/page', persona: 'member' },
    canaryIdOrMarker: storedMarker,
    surfaceKind: 'stored_xss',
  })
}

test('prove_canary_or_redirect: planted marker confirms on the stored sink and is rejected when sanitised', async () => {
  const vuln = await commentsFixture(false)
  try {
    const compiled = storedXssProof(vuln.origin)
    assertIdentifierBound(compiled)
    assert.equal(compiled.spaCatchallControl, true)
    const res = await verify(compiled, grantFor([vuln.origin]))
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
  } finally { await vuln.close() }

  const hardened = await commentsFixture(true)
  try {
    const res = await verify(storedXssProof(hardened.origin), grantFor([hardened.origin]))
    assert.equal(res.verdict, 'dismissed', String(res.outcome.reason))
    assert.equal(res.outcome.confirmed, false)
  } finally { await hardened.close() }
})

// ---------------------------------------------------------------------------
// 4b. External redirect
// ---------------------------------------------------------------------------

function redirectFixture(hardened: boolean) {
  return fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname !== '/go') return json(res, 404, { error: 'not_found' })
    const next = url.searchParams.get('next') ?? '/home'
    const external = /^https?:\/\//i.test(next)
    res.statusCode = 302
    res.setHeader('Location', hardened && external ? '/home' : next)
    res.end()
  })
}

function redirectProof(origin: string): CompiledProof {
  return proveCanaryOrRedirect({
    origin,
    plantStep: { method: 'GET', pathAndQuery: '/go?next=/home' },
    triggerStep: { method: 'GET', pathAndQuery: '/go?next=https://evil.example/landing', followRedirects: false },
    canaryIdOrMarker: 'evil.example',
    surfaceKind: 'open_redirect',
  })
}

test('prove_canary_or_redirect: external Location confirms and a hardened same-origin redirect dismisses', async () => {
  const vuln = await redirectFixture(false)
  try {
    const compiled = redirectProof(vuln.origin)
    assertIdentifierBound(compiled)
    assert.equal(compiled.spaCatchallControl, false)
    const res = await verify(compiled, grantFor([vuln.origin]))
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
  } finally { await vuln.close() }

  const hardened = await redirectFixture(true)
  try {
    const res = await verify(redirectProof(hardened.origin), grantFor([hardened.origin]))
    assert.equal(res.verdict, 'dismissed', String(res.outcome.reason))
    assert.equal(res.outcome.confirmed, false)
  } finally { await hardened.close() }
})

// ---------------------------------------------------------------------------
// 5. Validation and repair feedback
// ---------------------------------------------------------------------------

test('validation: missing or ambiguous identifiers throw ProofCompileError with a suggested fix', () => {
  const base = {
    origin: 'https://app.example',
    ownerPersona: 'owner',
    attackerPersona: 'attacker',
    endpoint: '/api/orders/{resourceId}',
    resourceId: '42',
    identifierPath: 'id',
  }

  assert.throws(() => proveAuthzReadDiff({ ...base, resourceId: '' }), (err: unknown) => {
    assert.ok(err instanceof ProofCompileError)
    assert.equal(err.issues[0]?.field, 'resourceId')
    assert.match(err.issues[0]?.fix ?? '', /concrete/i)
    return true
  })
  assert.throws(() => proveAuthzReadDiff({ ...base, resourceId: '{{id}}' }), (err: unknown) => {
    assert.ok(err instanceof ProofCompileError)
    assert.equal(err.issues[0]?.code, 'nonspecific_identifier')
    return true
  })
  assert.throws(() => proveAuthzReadDiff({ ...base, identifierPath: 'status' }), (err: unknown) => {
    assert.ok(err instanceof ProofCompileError)
    assert.equal(err.issues[0]?.field, 'identifierPath')
    assert.match(err.issues[0]?.fix ?? '', /dot path/i)
    return true
  })
  assert.throws(() => proveAuthzReadDiff({ ...base, endpoint: '/api/orders' }), (err: unknown) => {
    assert.ok(err instanceof ProofCompileError)
    assert.equal(err.issues[0]?.code, 'ambiguous_scope')
    return true
  })
  assert.throws(() => proveAuthzReadDiff({ ...base, attackerPersona: 'owner' }), (err: unknown) => {
    assert.ok(err instanceof ProofCompileError)
    assert.equal(err.issues[0]?.code, 'conflicting_roles')
    return true
  })
})

test('validation: cross-tool structural errors are structured for one-turn repair', () => {
  const state = validateProofInput('prove_state_mutation_diff', {
    origin: 'https://app.example',
    beforeRead: { method: 'GET', pathAndQuery: '/a' },
    probeMutation: { method: 'GET', pathAndQuery: '/a' },
    afterRead: { method: 'GET', pathAndQuery: '/b' },
    changedFieldPath: 'role',
  })
  assert.equal(state.ok, false)
  if (!state.ok) {
    assert.ok(state.errors.some(issue => issue.field === 'probeMutation.method'))
    assert.ok(state.errors.some(issue => issue.field === 'afterRead.pathAndQuery' && issue.code === 'ambiguous_scope'))
    assert.ok(state.errors.every(issue => issue.fix.length > 5))
  }

  const invariant = validateProofInput('prove_business_invariant', {
    origin: 'https://app.example',
    controlFlow: { method: 'POST', pathAndQuery: '/transfer', jsonBody: { amount: 1 } },
    probeFlow: { method: 'POST', pathAndQuery: '/transfer', jsonBody: { amount: 2 } },
    readback: { method: 'GET', pathAndQuery: '/balance' },
    fieldPath: 'balance',
    op: 'gte',
    baselineRef: 'not-a-number',
  })
  assert.equal(invariant.ok, false)
  if (!invariant.ok) {
    assert.ok(invariant.errors.some(issue => issue.field === 'baselineRef' && issue.code === 'invalid'))
  }

  const redirect = validateProofInput('prove_canary_or_redirect', {
    origin: 'https://app.example',
    plantStep: { method: 'GET', pathAndQuery: '/go?next=/home' },
    triggerStep: { method: 'GET', pathAndQuery: '/go?next=https://evil.example', followRedirects: true },
    canaryIdOrMarker: 'evil.example',
    surfaceKind: 'open_redirect',
  })
  assert.equal(redirect.ok, false)
  if (!redirect.ok) {
    assert.ok(redirect.errors.some(issue => issue.field === 'triggerStep.followRedirects'))
  }

  const canary = validateProofInput('prove_canary_or_redirect', {
    origin: 'https://app.example',
    plantStep: { method: 'POST', pathAndQuery: '/comments', jsonBody: { text: 'marker' } },
    triggerStep: { method: 'GET', pathAndQuery: '/page' },
    canaryIdOrMarker: 'test',
    surfaceKind: 'stored_xss',
  })
  assert.equal(canary.ok, false)
  if (!canary.ok) {
    assert.ok(canary.errors.some(issue => issue.field === 'canaryIdOrMarker' && issue.code === 'nonspecific_identifier'))
  }

  assert.equal(validateProofInput('not_a_tool', {}).ok, false)
  assert.equal(validateProofInput('prove_authz_read_diff', null).ok, false)
})

// ---------------------------------------------------------------------------
// 6. Determinism + no status-only output + catch-all policy
// ---------------------------------------------------------------------------

test('compilers: deterministic output, stable key order, no status-only assertion', () => {
  const origin = 'https://app.example'
  const first = authzProof(origin)
  const second = authzProof(origin)
  assert.equal(JSON.stringify(first), JSON.stringify(second))
  assert.deepEqual(Object.keys(first.spec), [
    'version', 'kind', 'origin', 'title', 'category', 'cwe', 'severity', 'severityRationale',
    'impact', 'remediation', 'recheckInstructions', 'assertionsJq', 'requireControlNonError',
    'spaCatchallControl', 'steps',
  ])
  assert.deepEqual(first.spec.steps.map(step => step.id), ['control', 'probe'])

  const proofs = [
    first,
    stateProof(origin),
    invariantProof(origin),
    storedXssProof(origin),
    redirectProof(origin),
  ]
  for (const proof of proofs) assertIdentifierBound(proof)
  assert.equal(JSON.stringify(describeProofTools()), JSON.stringify(describeProofTools()))
})

test('prove_state_mutation_diff: an optional benign control arm asserts the unchanged field', () => {
  const compiled = proveStateMutationDiff({
    origin: 'https://app.example',
    beforeRead: { method: 'GET', pathAndQuery: '/api/accounts/7', persona: 'member' },
    controlMutation: { method: 'PATCH', pathAndQuery: '/api/accounts/7', persona: 'member', jsonBody: { role: 'user' } },
    controlAfterRead: { method: 'GET', pathAndQuery: '/api/accounts/7', persona: 'member' },
    probeMutation: { method: 'PATCH', pathAndQuery: '/api/accounts/7', persona: 'attacker', jsonBody: { role: 'admin' } },
    afterRead: { method: 'GET', pathAndQuery: '/api/accounts/7', persona: 'member' },
    changedFieldPath: 'role',
    op: 'changed',
  })
  assert.deepEqual(compiled.spec.steps.map(step => [step.id, step.role]), [
    ['control_before', 'control'], ['control_mutate', 'control'], ['control_after', 'control'],
    ['probe_mutate', 'probe'], ['after_read', 'control'],
  ])
  assert.match(compiled.assertionsJq, /control_after\.json\.role/)
  assert.deepEqual(compiled.warnings, [])
})

test('prove_business_invariant: a step-field baseline compiles to a bound jq reference', () => {
  const compiled = proveBusinessInvariant({
    origin: 'https://app.example',
    setupSteps: [{ id: 'seed', method: 'GET', pathAndQuery: '/api/limits' }],
    controlFlow: [{ method: 'POST', pathAndQuery: '/api/transfer', jsonBody: { amount: 1 } }],
    probeFlow: [{ method: 'POST', pathAndQuery: '/api/transfer', jsonBody: { amount: 999 } }],
    readback: { method: 'GET', pathAndQuery: '/api/balance' },
    fieldPath: 'balance',
    op: 'gte',
    baselineRef: 'seed.limit',
  })
  assert.match(compiled.assertionsJq, /\.steps\.seed\.json\.limit/)
  assert.deepEqual(compiled.spec.steps[0]!.id, 'seed')
})

test('compilers: catch-all control is enabled for HTML-prone surfaces only', () => {
  const origin = 'https://app.example'
  assert.equal(authzProof(origin).spaCatchallControl, true)
  assert.equal(stateProof(origin).spaCatchallControl, true)
  assert.equal(invariantProof(origin).spaCatchallControl, true)
  assert.equal(storedXssProof(origin).spaCatchallControl, true)
  assert.equal(redirectProof(origin).spaCatchallControl, false)

  const ssrf = proveCanaryOrRedirect({
    origin,
    plantStep: { method: 'POST', pathAndQuery: '/fetch-target', jsonBody: { url: '{{canary_url}}' } },
    triggerStep: { method: 'GET', pathAndQuery: '/fetch' },
    canaryIdOrMarker: '{{canary_url}}',
    surfaceKind: 'ssrf',
  })
  assert.equal(ssrf.spaCatchallControl, false)
  assert.match(ssrf.assertionsJq, /\.canary\.probeTriggered/)
  assert.notEqual(classifyHttpChainAssertion(ssrf.assertionsJq), 'status_only')
})

// ---------------------------------------------------------------------------
// 7. Tool schema description snapshot
// ---------------------------------------------------------------------------

test('describeProofTools: stable tool list, required inputs and one-line usage', () => {
  const described = describeProofTools()
  assert.deepEqual(described.map(tool => tool.name), [...proofToolNames])
  assert.deepEqual(
    Object.fromEntries(described.map(tool => [tool.name, [...tool.inputSchema.required]])),
    {
      prove_authz_read_diff: ['origin', 'ownerPersona', 'attackerPersona', 'endpoint', 'resourceId', 'identifierPath'],
      prove_state_mutation_diff: ['origin', 'beforeRead', 'probeMutation', 'afterRead', 'changedFieldPath'],
      prove_business_invariant: ['origin', 'controlFlow', 'probeFlow', 'readback', 'fieldPath', 'op', 'baselineRef'],
      prove_canary_or_redirect: ['origin', 'plantStep', 'triggerStep', 'canaryIdOrMarker', 'surfaceKind'],
    },
  )
  for (const tool of described) {
    assert.ok(tool.usage.length > 20)
    for (const field of tool.inputSchema.required) {
      assert.ok(tool.inputSchema.properties[field], `${tool.name} is missing an input schema for ${field}`)
    }
  }
  assert.equal(described[0]!.inputSchema.properties.identifierPath!.type, 'string')
  assert.deepEqual(described[2]!.inputSchema.properties.op!.enum, ['lt', 'lte', 'gt', 'gte', 'eq', 'neq'])
})
