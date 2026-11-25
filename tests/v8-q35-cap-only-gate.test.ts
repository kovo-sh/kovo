/**
 * Regression suite for Queue #35 (`v8-q35-cap-only-gate`):
 * Standalone 0-hop capability-only / intermediate-draft creation gate across
 * `verify-claims.ts` and `verify-prove-handlers.ts`.
 *
 * Defensive QA: verifies that standalone non-composite proofs (`boundary`, `impact`,
 * `structural_diff`, and raw `status`/`jsonpath`/`body_contains` claims) fail closed
 * with `rejectedBy: 'terminal_impact_unproven'` when they only demonstrate creation or
 * polling of an intermediate draft/queued/pending object or handle stub (e.g. HTTP 201
 * resource creation via parser differential) without terminal security impact, while
 * preserving 100% of legitimate single-hop findings and surfacing `endpoint` cleanly.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  TranscriptStore,
  detectIntermediateStub,
  evaluateClaims,
} from '../src/server/verify-claims.ts'
import type { VerifyClaim } from '../src/server/verify-claims.ts'
import {
  handleProveAccessBoundary,
  handleProveDifferential,
  handleProveInjection,
  handleProvePersistedMutation,
} from '../src/server/verify-prove-handlers.ts'
import type { ProveHandlerHost, ProveHttpExchangeResult } from '../src/server/verify-prove-handlers.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { VerifyContext } from '../worker/guardian_verify/guardian_verify.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN = 'http://127.0.0.1:49888'

function recordHttp(
  store: TranscriptStore,
  input: {
    method: string
    pathAndQuery: string
    status: number
    body: string
    role?: string
    personaHandle?: string | null
    actorRoleLabel?: string | null
    nonce?: string
  },
) {
  return store.record({
    op: 'http',
    startedAt: Date.now(),
    durationMs: 4,
    request: {
      origin: ORIGIN,
      method: input.method,
      pathAndQuery: input.pathAndQuery,
      headers: { 'content-type': 'application/json' },
      bodyBytes: 0,
      bodySha256: 'req000',
      ...(input.personaHandle !== undefined ? { personaHandle: input.personaHandle } : {}),
      ...(input.role ? { sessionRole: input.role } : {}),
      ...(input.actorRoleLabel !== undefined ? { actorRoleLabel: input.actorRoleLabel } : {}),
      nonce: input.nonce ?? 'n-q35',
    },
    response: {
      status: input.status,
      headers: { 'content-type': 'application/json' },
      bodyBytes: Buffer.byteLength(input.body),
      bodySha256: `sha_${input.status}_${Buffer.byteLength(input.body)}`,
      mediaType: 'application/json',
    },
    body: input.body,
  })
}

function makeInMemoryHost(
  responder: (args: Record<string, unknown>) => { status: number; body: string; personaHandle?: string | null; actorRoleLabel?: string | null },
): { host: ProveHandlerHost; transcript: TranscriptStore } {
  const transcript = new TranscriptStore()
  const host: ProveHandlerHost = {
    transcript,
    defaultOrigin: ORIGIN,
    canaryBroker: undefined,
    async runHttpExchange(args, nonce): Promise<ProveHttpExchangeResult> {
      const method = String(args.method ?? 'GET').toUpperCase()
      const pathAndQuery = String(args.path ?? '/')
      const res = responder(args)
      const rec = recordHttp(transcript, {
        method,
        pathAndQuery,
        status: res.status,
        body: res.body,
        role: typeof args.sessionGroupRole === 'string' ? args.sessionGroupRole : 'probe',
        personaHandle: res.personaHandle ?? (typeof args.persona === 'string' ? args.persona : null),
        actorRoleLabel: res.actorRoleLabel ?? null,
        nonce,
      })
      return {
        exchangeId: rec.exchangeId,
        status: res.status,
        method,
        pathAndQuery,
        headers: { 'content-type': 'application/json' },
        body: res.body,
        bodyPreview: res.body.slice(0, 512),
        bodyBytes: Buffer.byteLength(res.body),
        bodySha256: rec.response!.bodySha256,
        durationMs: 4,
        personaHandle: rec.request?.personaHandle ?? null,
      }
    },
    async runOob() { return {} },
    async runRace() { return { mode: 'http1-fallback', results: [] } },
    scrubRecord<T>(v: T): T { return v },
  }
  return { host, transcript }
}

// ============================================================================
// 1. Standalone intermediate-draft / queued-job creation MUST fail closed
// ============================================================================

test('rejects standalone parser-differential draft creation via boundary, structural_diff, persisted_mutation, and raw claims', async () => {
  // 1a. handleProveAccessBoundary: clean 403 -> dup-key 201 draft object (same actor)
  const { host: bHost, transcript: bStore } = makeInMemoryHost((args) => {
    const raw = String(args.body ?? '')
    const isDupKey = (raw.match(/"amountCents"/g) ?? []).length >= 2
    if (!isDupKey) return { status: 403, body: JSON.stringify({ error: 'amount exceeds policy' }), actorRoleLabel: 'member (org_a)' }
    return {
      status: 201,
      body: JSON.stringify({ id: 'obj_draft_1', status: 'draft', amountCents: 500000, tenantId: 'org_a' }),
      actorRoleLabel: 'member (org_a)',
    }
  })
  const bRes = await handleProveAccessBoundary(bHost, {
    controlPersona: 'member_a',
    probePersona: 'member_a',
    route: '/v1/disbursements',
    method: 'POST',
    controlOptions: { body: '{"amountCents":500000}' },
    probeOptions: { body: '{"amountCents":100,"amountCents":500000}' },
  }, 'n1') as { ok: boolean; rejectedBy: string | null; missingEvidence: string[]; endpoint: string | null; claim: VerifyClaim }
  assert.equal(bRes.ok, false)
  assert.equal(bRes.rejectedBy, 'terminal_impact_unproven')
  assert.ok(bRes.missingEvidence.includes('terminal_impact_unproven'))
  assert.equal(bRes.endpoint, '/v1/disbursements')
  const bOracle = evaluateClaims(bStore, [bRes.claim], { claimedImpact: 'authorization', claimedBoundary: 'access' })
  assert.equal(bOracle.passed, false)
  assert.equal(bOracle.rejectedBy, 'terminal_impact_unproven')
  assert.equal(bOracle.endpoint, '/v1/disbursements')

  // 1b. handleProveDifferential (structural_diff): 3 rounds clean 403 vs dup-key 201 draft
  const { host: dHost, transcript: dStore } = makeInMemoryHost((args) => {
    const raw = String(args.body ?? '')
    const isDupKey = (raw.match(/"amountCents"/g) ?? []).length >= 2
    if (!isDupKey) return { status: 403, body: JSON.stringify({ error: 'amount exceeds policy' }), actorRoleLabel: 'member (org_a)' }
    return {
      status: 201,
      body: JSON.stringify({ id: '00000000-0000-4000-8000-000000000001', status: 'draft', amountCents: 500000 }),
      actorRoleLabel: 'member (org_a)',
    }
  })
  const dRes = await handleProveDifferential(dHost, {
    control: { target: '/v1/disbursements', method: 'POST', as: 'member_a', body: '{"amountCents":500000}' },
    variant: { target: '/v1/disbursements', method: 'POST', as: 'member_a', body: '{"amountCents":100,"amountCents":500000}' },
    mode: 'boolean',
    rounds: 3,
  }, 'n2') as { ok: boolean; rejectedBy: string | null; missingEvidence: string[]; endpoint: string | null; claim: VerifyClaim }
  assert.equal(dRes.ok, false)
  assert.equal(dRes.rejectedBy, 'terminal_impact_unproven')
  assert.ok(dRes.missingEvidence.includes('terminal_impact_unproven'))
  assert.equal(dRes.endpoint, '/v1/disbursements')
  const dOracle = evaluateClaims(dStore, [dRes.claim], { claimedImpact: 'other', claimedBoundary: 'other' })
  assert.equal(dOracle.passed, false)
  assert.equal(dOracle.rejectedBy, 'terminal_impact_unproven')

  // 1c. handleProvePersistedMutation: same-tenant draft creation added to collection readback
  let createdDraft = false
  const { host: mHost, transcript: mStore } = makeInMemoryHost((args) => {
    const method = String(args.method ?? 'GET').toUpperCase()
    if (method === 'GET') {
      const items = createdDraft
        ? [{ id: 'obj_0', status: 'approved', amountCents: 100 }, { id: 'obj_1', status: 'draft', amountCents: 500000, tenantId: 'org_a' }]
        : [{ id: 'obj_0', status: 'approved', amountCents: 100 }]
      return { status: 200, body: JSON.stringify({ count: items.length, items }), actorRoleLabel: 'member (org_a)' }
    }
    createdDraft = true
    return {
      status: 201,
      body: JSON.stringify({ id: 'obj_1', status: 'draft', amountCents: 500000, tenantId: 'org_a' }),
      actorRoleLabel: 'member (org_a)',
    }
  })
  const mRes = await handleProvePersistedMutation(mHost, {
    readRoute: '/v1/disbursements',
    mutation: { target: '/v1/disbursements', method: 'POST', as: 'member_a', body: '{"amountCents":100,"amountCents":500000}' },
    fieldPath: 'items[1].status',
    expectDelta: 'draft',
    readPersona: 'member_a',
    impactClass: 'authorization',
  }, 'n3') as { ok: boolean; rejectedBy: string | null; missingEvidence: string[]; endpoint: string | null; claim: VerifyClaim }
  assert.equal(mRes.ok, false)
  assert.equal(mRes.rejectedBy, 'terminal_impact_unproven')
  assert.ok(mRes.missingEvidence.includes('terminal_impact_unproven'))
  assert.equal(mRes.endpoint, '/v1/disbursements')
  const mOracle = evaluateClaims(mStore, [mRes.claim], { claimedImpact: 'authorization', claimedBoundary: 'access' })
  assert.equal(mOracle.passed, false)
  assert.equal(mOracle.rejectedBy, 'terminal_impact_unproven')

  // 1d. Raw standalone claims (`status` + `jsonpath`) on 201 draft creation + same-actor draft readback
  const rawStore = new TranscriptStore()
  const before = recordHttp(rawStore, { method: 'GET', pathAndQuery: '/v1/disbursements', status: 200, role: 'setup', personaHandle: 'member_a', actorRoleLabel: 'member (org_a)', body: JSON.stringify({ items: [] }) })
  const ctrl = recordHttp(rawStore, { method: 'POST', pathAndQuery: '/v1/disbursements', status: 403, role: 'control', personaHandle: 'member_a', actorRoleLabel: 'member (org_a)', body: JSON.stringify({ error: 'policy_denied' }) })
  const probe = recordHttp(rawStore, { method: 'POST', pathAndQuery: '/v1/disbursements', status: 201, role: 'probe', personaHandle: 'member_a', actorRoleLabel: 'member (org_a)', body: JSON.stringify({ id: 'obj_2', status: 'pending_approval', amountCents: 500000, requiresApproval: true }) })
  const after = recordHttp(rawStore, { method: 'GET', pathAndQuery: '/v1/disbursements', status: 200, role: 'control', personaHandle: 'member_a', actorRoleLabel: 'member (org_a)', body: JSON.stringify({ items: [{ id: 'obj_2', status: 'pending_approval', amountCents: 500000 }] }) })
  const rawOracle = evaluateClaims(rawStore, [
    { kind: 'status', exchangeId: before.exchangeId, expected: 200 },
    { kind: 'status', exchangeId: ctrl.exchangeId, expected: 403 },
    { kind: 'status', exchangeId: probe.exchangeId, expected: 201 },
    { kind: 'jsonpath', exchangeId: probe.exchangeId, path: 'status', equals: 'pending_approval' },
    { kind: 'status', exchangeId: after.exchangeId, expected: 200 },
  ], { claimedImpact: 'other', claimedBoundary: 'other' })
  assert.equal(rawOracle.passed, false)
  assert.equal(rawOracle.rejectedBy, 'terminal_impact_unproven')
  assert.ok(rawOracle.missingEvidence?.includes('terminal_impact_unproven'))
  assert.equal(rawOracle.endpoint, '/v1/disbursements')
})

test('rejects standalone queued async export / handle stub creation without downloading target data', async () => {
  const store = new TranscriptStore()
  const ctrl = recordHttp(store, { method: 'POST', pathAndQuery: '/v1/orgs/org_b/exports', status: 403, role: 'control', personaHandle: 'member_a', actorRoleLabel: 'member (org_a)', body: JSON.stringify({ error: 'forbidden' }) })
  const queued = recordHttp(store, { method: 'POST', pathAndQuery: '/v1/orgs/org_b/exports', status: 202, role: 'probe', personaHandle: 'member_a', actorRoleLabel: 'member (org_a)', body: JSON.stringify({ jobId: 'job_99', status: 'queued', tenant: 'org_b' }) })
  const poll = recordHttp(store, { method: 'GET', pathAndQuery: '/v1/exports/job_99', status: 200, role: 'control', personaHandle: 'member_a', actorRoleLabel: 'member (org_a)', body: JSON.stringify({ job: { id: 'job_99', status: 'ready', artifactKey: 'org_b/data.csv' } }) })

  assert.equal(detectIntermediateStub(queued, store.body(queued.exchangeId)).pureJobStub, true)
  assert.equal(detectIntermediateStub(poll, store.body(poll.exchangeId)).pureJobStub, true)

  const boundaryOracle = evaluateClaims(store, [
    { kind: 'boundary', boundaryClass: 'access', controlExchangeId: ctrl.exchangeId, probeExchangeId: queued.exchangeId },
  ], { claimedImpact: 'authorization', claimedBoundary: 'access' })
  assert.equal(boundaryOracle.passed, false)
  assert.equal(boundaryOracle.rejectedBy, 'terminal_impact_unproven')

  const rawOracle = evaluateClaims(store, [
    { kind: 'status', exchangeId: queued.exchangeId, expected: 202 },
    { kind: 'status', exchangeId: poll.exchangeId, expected: 200 },
  ])
  assert.equal(rawOracle.passed, false)
  assert.equal(rawOracle.rejectedBy, 'terminal_impact_unproven')
})

// ============================================================================
// 2. Legitimate single-hop findings MUST continue to pass without regression
// ============================================================================

test('preserves legitimate single-hop BOLA read (even of a victim draft), BFLA finalized mutation, mass assignment, SQLi boolean diff, and SSTI evaluated diff', async () => {
  // 2a. BOLA cross-tenant GET read of another tenant's draft invoice
  const bolaStore = new TranscriptStore()
  const bolaCtrl = recordHttp(bolaStore, { method: 'GET', pathAndQuery: '/api/invoices/inv_victim', status: 403, role: 'control', personaHandle: 'viewer_b', actorRoleLabel: 'viewer (org_b)', body: JSON.stringify({ error: 'forbidden' }) })
  const bolaProbe = recordHttp(bolaStore, { method: 'GET', pathAndQuery: '/api/invoices/inv_victim', status: 200, role: 'probe', personaHandle: 'member_b', actorRoleLabel: 'member (org_b)', body: JSON.stringify({ id: 'inv_victim', tenantId: 'org_a', status: 'draft', amountCents: 75000, email: 'finance@org-a.example' }) })
  const bolaOracle = evaluateClaims(bolaStore, [
    { kind: 'boundary', boundaryClass: 'access', controlExchangeId: bolaCtrl.exchangeId, probeExchangeId: bolaProbe.exchangeId },
  ], { claimedImpact: 'authorization', claimedBoundary: 'access' })
  assert.equal(bolaOracle.passed, true, bolaOracle.failures.join('; '))
  assert.equal(bolaOracle.endpoint, '/api/invoices/inv_victim')

  // 2b. Finalized privileged state transition (POST approve -> 200 approved)
  const approveStore = new TranscriptStore()
  const approveCtrl = recordHttp(approveStore, { method: 'POST', pathAndQuery: '/v1/disbursements/obj_1/approve', status: 403, role: 'control', personaHandle: 'viewer_a', actorRoleLabel: 'viewer (org_a)', body: JSON.stringify({ error: 'forbidden' }) })
  const approveProbe = recordHttp(approveStore, { method: 'POST', pathAndQuery: '/v1/disbursements/obj_1/approve', status: 200, role: 'probe', personaHandle: 'member_a', actorRoleLabel: 'member (org_a)', body: JSON.stringify({ id: 'obj_1', status: 'approved', amountCents: 500000 }) })
  const approveOracle = evaluateClaims(approveStore, [
    { kind: 'boundary', boundaryClass: 'access', controlExchangeId: approveCtrl.exchangeId, probeExchangeId: approveProbe.exchangeId },
  ], { claimedImpact: 'authorization', claimedBoundary: 'access' })
  assert.equal(approveOracle.passed, true, approveOracle.failures.join('; '))

  // 2c. Legitimate persisted mutation (mass assignment: role member -> admin)
  let userRole = 'member'
  const { host: maHost, transcript: maStore } = makeInMemoryHost((args) => {
    if (String(args.method ?? 'GET').toUpperCase() === 'GET') {
      return { status: 200, body: JSON.stringify({ id: 'u1', role: userRole, tenantId: 'org_a' }), actorRoleLabel: 'member (org_a)' }
    }
    userRole = 'admin'
    return { status: 200, body: JSON.stringify({ ok: true }), actorRoleLabel: 'member (org_a)' }
  })
  const maRes = await handleProvePersistedMutation(maHost, {
    readRoute: '/api/users/me',
    mutation: { target: '/api/users/me', method: 'PATCH', as: 'member_a', body: { role: 'admin' } },
    fieldPath: 'role',
    expectDelta: 'admin',
    readPersona: 'member_a',
    impactClass: 'mass_assignment',
  }, 'n-ma') as { ok: boolean; endpoint: string | null; claim: VerifyClaim }
  assert.equal(maRes.ok, true)
  assert.equal(maRes.endpoint, '/api/users/me')
  assert.equal(evaluateClaims(maStore, [maRes.claim], { claimedImpact: 'mass_assignment' }).passed, true)

  // 2d. Legitimate boolean SQLi structural_diff (POST search 200 vs 200)
  const { host: sqliHost, transcript: sqliStore } = makeInMemoryHost((args) => {
    const raw = String(args.body ?? '')
    const items = raw.includes('1=1') ? [{ id: 1, name: 'Widget' }, { id: 2, name: 'Gadget' }] : [{ id: 1, name: 'Widget' }]
    return { status: 200, body: JSON.stringify({ items, total: items.length }) }
  })
  const sqliRes = await handleProveDifferential(sqliHost, {
    control: { target: '/api/search', method: 'POST', body: { q: 'w' } },
    variant: { target: '/api/search', method: 'POST', body: { q: "w' OR 1=1--" } },
    mode: 'boolean',
    rounds: 3,
  }, 'n-sqli') as { ok: boolean; endpoint: string | null; claim: VerifyClaim }
  assert.equal(sqliRes.ok, true)
  assert.equal(sqliRes.endpoint, '/api/search')
  assert.equal(evaluateClaims(sqliStore, [sqliRes.claim], { claimedImpact: 'injection' }).passed, true)

  // 2e. Legitimate SSTI evaluated-expression differential even on a POST returning a draft object
  const { host: sstiHost, transcript: sstiStore } = makeInMemoryHost((args) => {
    const raw = String(args.body ?? '')
    const rendered = raw.includes('7001*79') ? '553079' : 'plain-preview'
    return { status: 201, body: JSON.stringify({ id: '00000000-0000-4000-8000-000000000009', status: 'draft', rendered }) }
  })
  const sstiRes = await handleProveInjection(sstiHost, {
    url: '/api/templates/preview',
    method: 'POST',
    controlBody: { tpl: 'plain-preview' },
    probeBody: { tpl: '{{7001*79}}' },
    expectedOutput: '553079',
    vulnClass: 'ssti',
  }, 'n-ssti') as { ok: boolean; endpoint: string | null; claims: VerifyClaim[] }
  assert.equal(sstiRes.ok, true)
  assert.equal(sstiRes.endpoint, '/api/templates/preview')
  const sstiOracle = evaluateClaims(sstiStore, sstiRes.claims, { claimedImpact: 'injection' })
  assert.equal(sstiOracle.passed, true, sstiOracle.failures.join('; '))

  // 2f. Legitimate cross-tenant write (member_b mutates org_a, owner_a reads it back)
  let foreignNote = 'baseline'
  const { host: ctHost, transcript: ctStore } = makeInMemoryHost((args) => {
    const method = String(args.method ?? 'GET').toUpperCase()
    const persona = String(args.persona ?? '')
    if (method === 'GET') {
      return { status: 200, body: JSON.stringify({ id: 'rec_1', tenantId: 'org_a', status: 'draft', note: foreignNote }), actorRoleLabel: 'owner (org_a)' }
    }
    if (persona === 'member_b') foreignNote = 'cross-tenant-marker'
    return { status: 201, body: JSON.stringify({ id: 'rec_1', tenantId: 'org_a', status: 'draft', note: foreignNote }), actorRoleLabel: 'member (org_b)' }
  })
  const ctRes = await handleProvePersistedMutation(ctHost, {
    readRoute: '/api/records/rec_1',
    mutation: { target: '/api/records/rec_1', method: 'PUT', as: 'member_b', body: { note: 'cross-tenant-marker' } },
    fieldPath: 'note',
    expectDelta: 'cross-tenant-marker',
    readPersona: 'owner_a',
    impactClass: 'authorization',
    resourceTenant: 'org_a',
  }, 'n-ct') as { ok: boolean; endpoint: string | null; claim: VerifyClaim }
  assert.equal(ctRes.ok, true)
  assert.equal(ctRes.endpoint, '/api/records/rec_1')
  const ctOracle = evaluateClaims(ctStore, [ctRes.claim], { claimedImpact: 'authorization', claimedBoundary: 'access' })
  assert.equal(ctOracle.passed, true, ctOracle.failures.join('; '))
  assert.equal(ctOracle.endpoint, '/api/records/rec_1')
})

// ============================================================================
// 3. End-to-end RPC bridge + VerifyContext integration & invariants
// ============================================================================

test('end-to-end VerifyRpcServer + VerifyContext rejects 201 draft parser-differential and surfaces endpoint', async (t) => {
  const srv = createServer((req: IncomingMessage, res: ServerResponse) => {
    let raw = ''
    req.setEncoding('utf8')
    req.on('data', c => { raw += c })
    req.on('end', () => {
      const isDup = (raw.match(/"amountCents"/g) ?? []).length >= 2
      const status = isDup ? 201 : 403
      const payload = isDup
        ? JSON.stringify({ id: '00000000-0000-4000-8000-000000000011', status: 'draft', amountCents: 500000 })
        : JSON.stringify({ error: 'amount_policy_blocked' })
      res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) })
      res.end(payload)
    })
  })
  const port = await new Promise<number>((resolvePort, reject) => {
    srv.once('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address()
      if (!addr || typeof addr === 'string') reject(new Error('no port'))
      else resolvePort(addr.port)
    })
  })
  const origin = `http://127.0.0.1:${port}`
  t.after(() => new Promise<void>(r => { srv.closeAllConnections(); srv.close(() => r()) }))

  const persona: ResolvedPersona = {
    id: 'p-member', handle: 'member_a', roleLabel: 'member (org_a)',
    originAllowlist: [origin], authKind: 'bearer', headerName: null, secret: 'tok-q35-member', canaryMarkers: [],
  }
  const grant: Grant = {
    origin, tier: 3, allowLocalLab: true, allowedPorts: [port], maxRpsPerOrigin: 200,
    personas: new Map([['member_a', persona]]),
    canRead: c => c === origin,
    isStateChangeApproved: () => true,
    audit: () => {},
  }
  const rpcServer = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant,
    runId: `run-q35-cap-only-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assign-q35-cap-only',
    targetOrigins: [origin],
  })
  await rpcServer.start()
  t.after(() => rpcServer.close())

  const keys = [VERIFY_RPC_SOCKET_ENV, VERIFY_RPC_TOKEN_ENV, VERIFY_RPC_CONTEXT_ENV, VERIFY_NONCE_ENV] as const
  const prev = keys.map(k => process.env[k])
  process.env[VERIFY_RPC_SOCKET_ENV] = rpcServer.socketPath
  process.env[VERIFY_RPC_TOKEN_ENV] = join(rpcServer.hostDir, 'token')
  process.env[VERIFY_RPC_CONTEXT_ENV] = join(rpcServer.hostDir, 'context.json')
  process.env[VERIFY_NONCE_ENV] = rpcServer.nonce
  t.after(() => keys.forEach((k, i) => { if (prev[i] === undefined) delete process.env[k]; else process.env[k] = prev[i] }))

  const ctx = new VerifyContext()
  const boundaryProof = await ctx.prove_access_boundary({
    controlPersona: 'member_a',
    probePersona: 'member_a',
    route: '/v1/disbursements',
    method: 'POST',
    controlOptions: { body: '{"amountCents":500000}' },
    probeOptions: { body: '{"amountCents":100,"amountCents":500000}' },
  })
  assert.equal(boundaryProof.ok, false)
  assert.equal(boundaryProof.rejectedBy, 'terminal_impact_unproven')
  assert.ok(boundaryProof.missingEvidence.includes('terminal_impact_unproven'))

  const diffProof = await ctx.prove_boolean_or_timing_diff({
    control: { target: '/v1/disbursements', method: 'POST', as: 'member_a', body: '{"amountCents":500000}' },
    variant: { target: '/v1/disbursements', method: 'POST', as: 'member_a', body: '{"amountCents":100,"amountCents":500000}' },
    mode: 'boolean',
    rounds: 2,
  })
  assert.equal(diffProof.ok, false)
  assert.equal(diffProof.rejectedBy, 'terminal_impact_unproven')
  assert.ok(diffProof.missingEvidence.includes('terminal_impact_unproven'))

  const oracle = evaluateClaims(rpcServer.transcript, ctx.claims)
  assert.equal(oracle.passed, false)
  assert.equal(oracle.rejectedBy, 'terminal_impact_unproven')
  assert.equal(oracle.endpoint, '/v1/disbursements')
})

test('LOC ceilings and zero v8 benchmark contamination hold for leased files', () => {
  const loc = (rel: string) => readFileSync(join(REPO_ROOT, rel), 'utf8').trimEnd().split('\n').length
  assert.ok(loc('src/server/verify-claims.ts') <= 2300, `verify-claims.ts exceeded 2300 LOC: ${loc('src/server/verify-claims.ts')}`)
  assert.ok(loc('src/server/verify-prove-handlers.ts') <= 2300, `verify-prove-handlers.ts exceeded 2300 LOC: ${loc('src/server/verify-prove-handlers.ts')}`)
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `Contamination hits: ${JSON.stringify(scan.hits)}`)
  assert.equal(scan.hits.length, 0, `Contamination hits: ${JSON.stringify(scan.hits)}`)
})
