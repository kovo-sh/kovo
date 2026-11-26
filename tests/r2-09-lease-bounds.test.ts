/**
 * Regression & behavioral suite for R2-09 (Bounded Scoped Approval Leases):
 * - v11 migration adding typed `lease_scope`, `max_uses`, `cross_persona` with conservative backfill
 *   (legacy '/x/**' rows stay 'route', never widened into 'prefix'; only host sentinel -> 'host_nondestructive')
 * - Required finite TTL (default 30m, bounded) + expiry denial
 * - Required finite `maxUses` (25 route / 50 prefix & host) + atomic exhaustion denial
 * - Default persona binding + explicit `crossPersona: true` opt-in across store & RequestAdmissionEngine
 * - R2-01 mutation classification rejection (`isStructuralMutation`, `jsonrpc_destructive`,
 *   `jsonrpc_malformed`, `graphql_mutation_or_unverified`) from durable lease eligibility
 * - Honest original `riskLevel` audit attribution on bulk-approved cards (never hardcoded 'low')
 * - Server-side blast-radius preview computed over the run's real `endpoints` inventory
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import {
  DEFAULT_APPROVAL_LEASE_TTL_MS,
  DEFAULT_HOST_LEASE_MAX_USES,
  DEFAULT_PREFIX_LEASE_MAX_USES,
  DEFAULT_ROUTE_LEASE_MAX_USES,
  HOST_NONDESTRUCTIVE_LEASE_METHOD,
  HOST_NONDESTRUCTIVE_LEASE_PATTERN,
  MAX_APPROVAL_LEASE_TTL_MS,
  MAX_APPROVAL_LEASE_USES,
  newRun,
  runCommand,
} from '../src/domain.ts'
import {
  classifyRequestMutation,
  isDurableRouteLeaseEligible,
  RequestAdmissionEngine,
} from '../src/server/request-admission.ts'
import * as tables from '../src/server/schema.ts'
import { Store, STORE_SCHEMA_VERSION } from '../src/server/store.ts'

const ORIGIN = 'https://app.r2-09.example'
const OTHER_ORIGIN = 'https://other.r2-09.example'

function makeStore(t: test.TestContext): { store: Store; dir: string; dbPath: string } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r2-09-lease-bounds-'))
  const dbPath = join(dir, 'kovo.db')
  const store = new Store(dbPath)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return { store, dir, dbPath }
}

function setupTier3Run(store: Store, origins: string[] = [ORIGIN, OTHER_ORIGIN]) {
  const project = store.createProject({
    requestId: randomUUID(),
    name: `R2-09 Lease Bounds ${randomUUID().slice(0, 6)}`,
    environment: 'public',
    seeds: origins,
  })
  const created = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify bounded scoped approval leases and blast-radius preview',
    sourceMode: 'public',
    capabilityTier: 3,
    approvalPolicy: 'auto_review',
  }))
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId: created.id,
    action: 'discover',
    consent: true,
  }))
  const discovered = store.run(created.id)
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId: discovered.id,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    capabilityTier: 3,
    approvalPolicy: 'auto_review',
  }))
  store.updateRun(discovered.id, { phase: 'investigation', status: 'running' })
  const approvedRun = store.run(discovered.id)
  const worker = store.makeWorker(
    approvedRun,
    'investigation',
    approvedRun.candidates[0],
    'Lease bounds test worker',
    'Verify lease bounds',
    { sourceOrigins: origins },
  )
  return { projectId: project.id, runId: discovered.id, run: approvedRun, worker }
}

test('R2-09 v11 migration: conservatively backfills legacy /x/** rows as route (never prefix) and host sentinels as host_nondestructive', t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r2-09-v11-mig-'))
  const dbPath = join(dir, 'kovo.sqlite')
  t.after(() => { rmSync(dir, { recursive: true, force: true }) })

  // Seed a current DB, then downgrade approval_leases to pre-v11 shape (user_version = 10).
  const initial = new Store(dir)
  const { runId, run } = setupTier3Run(initial)
  const scopeRev = run.scopeRevision
  initial.close()

  const now = Date.now()
  const raw = new DatabaseSync(dbPath)
  try {
    raw.exec(`
      DROP TABLE approval_leases;
      CREATE TABLE approval_leases (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        scope_revision INTEGER NOT NULL,
        origin TEXT NOT NULL,
        method TEXT NOT NULL,
        route_pattern TEXT NOT NULL,
        persona_handle TEXT,
        status TEXT NOT NULL,
        source_approval_id TEXT,
        created_by TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER,
        uses INTEGER NOT NULL DEFAULT 0,
        last_used_at INTEGER
      );
      CREATE UNIQUE INDEX approval_leases_route
        ON approval_leases (run_id, origin, method, route_pattern, scope_revision);
      CREATE INDEX approval_leases_run ON approval_leases (run_id, status);
      PRAGMA user_version = 10;
    `)
    const ins = raw.prepare(`
      INSERT INTO approval_leases (
        id, run_id, scope_revision, origin, method, route_pattern, persona_handle,
        status, source_approval_id, created_by, created_at, updated_at, expires_at, uses, last_used_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', NULL, 'operator', ?, ?, NULL, 0, NULL)
    `)
    // Legacy glob-shaped pattern row from pre-e9e5ffd — MUST NOT widen into 'prefix'.
    ins.run('legacy-glob-row', runId, scopeRev, ORIGIN, 'POST', '/x/**', null, now, now)
    // Legacy exact route row with NULL expires_at.
    ins.run('legacy-route-row', runId, scopeRev, ORIGIN, 'POST', '/api/items/*', null, now, now)
    // Legacy explicit host non-destructive sentinel row.
    ins.run(
      'legacy-host-row', runId, scopeRev, OTHER_ORIGIN,
      HOST_NONDESTRUCTIVE_LEASE_METHOD, HOST_NONDESTRUCTIVE_LEASE_PATTERN, null, now, now,
    )
  } finally {
    raw.close()
  }

  // Reopen with Store to run v11 migration.
  const migrated = new Store(dir)
  t.after(() => { try { migrated.close() } catch { /* already closed */ } })
  const version = Number((migrated.client.prepare('PRAGMA user_version').get() as { user_version: number }).user_version)
  assert.equal(version, 11)
  assert.equal(STORE_SCHEMA_VERSION, 11)

  const leases = migrated.listApprovalLeases(runId, 'active')
  const byId = new Map(leases.map(l => [l.id, l]))

  const legacyGlob = byId.get('legacy-glob-row')!
  assert.equal(legacyGlob.leaseScope, 'route', 'legacy /x/** row MUST backfill conservatively as route, never prefix')
  assert.equal(legacyGlob.maxUses, DEFAULT_ROUTE_LEASE_MAX_USES)
  assert.equal(legacyGlob.crossPersona, false)
  assert.ok(typeof legacyGlob.expiresAt === 'number' && legacyGlob.expiresAt > now, 'active NULL expires_at must backfill finite TTL')

  // Legacy '/x/**' row backfilled as 'route' MUST NOT authorize subtree paths!
  assert.equal(migrated.leaseAuthorizes(runId, ORIGIN, 'POST', '/x/sub/path'), false, 'legacy /x/** row must NOT authorize /x/sub/path')
  assert.equal(migrated.leaseAuthorizes(runId, ORIGIN, 'POST', '/x/nested/deep/delete'), false)

  // Legacy route row still authorizes its exact normalized route.
  const legacyRoute = byId.get('legacy-route-row')!
  assert.equal(legacyRoute.leaseScope, 'route')
  assert.equal(migrated.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/items/42'), true)

  // Legacy host sentinel row backfilled as 'host_nondestructive'.
  const legacyHost = byId.get('legacy-host-row')!
  assert.equal(legacyHost.leaseScope, 'host_nondestructive')
  assert.equal(legacyHost.maxUses, DEFAULT_HOST_LEASE_MAX_USES)
  assert.equal(migrated.leaseAuthorizes(runId, OTHER_ORIGIN, 'PATCH', '/api/profile'), true)
  assert.equal(migrated.leaseAuthorizes(runId, OTHER_ORIGIN, 'DELETE', '/api/profile'), false)

  // CHECK constraint on lease_scope rejects invalid values.
  assert.throws(() => {
    migrated.client.prepare(`
      INSERT INTO approval_leases (
        id, run_id, scope_revision, origin, method, route_pattern, lease_scope,
        persona_handle, cross_persona, status, created_by, created_at, updated_at, expires_at, uses, max_uses
      ) VALUES ('bad-scope', ?, ?, ?, 'POST', '/bad', 'wildcard', NULL, 0, 'active', 'operator', ?, ?, ?, 0, 10)
    `).run(runId, scopeRev, ORIGIN, now, now, now + 60_000)
  }, /CHECK constraint/i)

  // Idempotent reopen preserves v11 state cleanly.
  migrated.close()
  const reopened = new Store(dir)
  t.after(() => { try { reopened.close() } catch { /* already closed */ } })
  assert.equal(reopened.migrationReport.applied.length, 0)
  assert.equal(reopened.leaseAuthorizes(runId, ORIGIN, 'POST', '/x/sub/path'), false)
})

test('R2-09 required TTL & expiry denial: durable leases always get finite expiresAt and deny once expired', t => {
  const { store } = makeStore(t)
  const { runId, run } = setupTier3Run(store)

  // Default durable lease gets finite 30-minute TTL and bounded maxUses.
  const before = Date.now()
  const defaultLease = store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/notes/123',
  })
  assert.ok(defaultLease.expiresAt !== null && Number.isFinite(defaultLease.expiresAt), 'durable lease must never have expiresAt=null')
  assert.ok(
    defaultLease.expiresAt! >= before + DEFAULT_APPROVAL_LEASE_TTL_MS - 1_000 &&
    defaultLease.expiresAt! <= Date.now() + DEFAULT_APPROVAL_LEASE_TTL_MS + 1_000,
    'default durable lease TTL should be 30 minutes',
  )
  assert.equal(defaultLease.maxUses, DEFAULT_ROUTE_LEASE_MAX_USES)
  assert.equal(defaultLease.leaseScope, 'route')

  // Null / non-finite / excessive TTL must be rejected.
  assert.throws(() => store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/null-ttl',
    expiresInMs: null as unknown as number,
  }), /finite expiresInMs/i)
  assert.throws(() => store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/huge-ttl',
    expiresInMs: MAX_APPROVAL_LEASE_TTL_MS + 60_000,
  }), /cannot exceed/i)

  // Expired lease is denied and flipped to status='expired'.
  const shortLease = store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/profile',
    expiresInMs: 60_000,
  })
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'PATCH', '/api/profile'), true)

  // Force expiry timestamp into the past.
  store.client.prepare('UPDATE approval_leases SET expires_at = ? WHERE id = ?').run(Date.now() - 10, shortLease.id)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'PATCH', '/api/profile'), false, 'expired lease must deny')
  const afterRow = store.listApprovalLeases(runId).find(l => l.id === shortLease.id)!
  assert.equal(afterRow.status, 'expired', 'expired lease should transition to expired status')
})

test('R2-09 maxUses exhaustion denial: atomic cap enforced on every use and transitions lease to expired', t => {
  const { store } = makeStore(t)
  const { runId, run } = setupTier3Run(store)

  // Reject invalid maxUses bounds.
  assert.throws(() => store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/capped',
    maxUses: 0,
  }), /maxUses/i)
  assert.throws(() => store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/capped',
    maxUses: MAX_APPROVAL_LEASE_USES + 1,
  }), /maxUses/i)

  const capped = store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/orders/1',
    maxUses: 3,
  })
  assert.equal(capped.maxUses, 3)

  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/orders/1'), true, 'use 1/3')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/orders/2'), true, 'use 2/3')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/orders/3'), true, 'use 3/3')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/orders/4'), false, 'use 4/3 MUST be denied')

  const exhausted = store.listApprovalLeases(runId).find(l => l.id === capped.id)!
  assert.equal(exhausted.uses, 3)
  assert.equal(exhausted.status, 'expired', 'exhausted lease must transition to expired')
  assert.equal(store.runDetail(runId).approvalLeases.some(l => l.id === capped.id), false, 'exhausted lease must leave active detail list')
})

test('R2-09 persona binding by default + explicit crossPersona opt-in across store, bulk-approval, and RequestAdmissionEngine', t => {
  const { store } = makeStore(t)
  const { runId, run, worker } = setupTier3Run(store)

  const aliceCard = store.createApprovalRequest(run, worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/projects/10',
    personaHandle: 'alice',
    rationale: 'Alice write probe',
    requestPreview: '{"title":"a"}',
    riskLevel: 'medium',
  })
  const bobCard = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/projects/20',
    personaHandle: 'bob',
    rationale: 'Bob write probe on same route',
    requestPreview: '{"title":"b"}',
    riskLevel: 'medium',
  })

  // Approve Alice's card with default route scope (persona-bound, crossPersona=false).
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: aliceCard.id,
    decision: 'approved',
    scope: 'route',
  }))

  // Bob's pending card MUST remain pending because default lease is persona-bound to Alice.
  assert.equal(store.getApprovalRequest(runId, aliceCard.id).status, 'approved')
  assert.equal(store.getApprovalRequest(runId, bobCard.id).status, 'pending', 'persona-bound lease must not bulk-approve other persona')

  // Direct store authorization checks.
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/projects/30', 'alice'), true, 'bound persona allowed')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/projects/30', 'bob'), false, 'cross-persona MUST be denied by default')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/projects/30', null), false, 'missing persona MUST be denied for persona-bound lease')

  // RequestAdmissionEngine enforces persona binding end-to-end.
  const engine = new RequestAdmissionEngine()
  const grant = {
    tier: 3 as const,
    canRead: (o: string) => o === ORIGIN,
    scopePolicy: store.scopePolicy(runId),
    approvalPolicy: 'auto_review' as const,
    approvalLeases: store.approvalLeaseAuthorizer(runId),
    isStateChangeApproved: () => false,
  }
  const aliceDecision = engine.admit({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/projects/40',
    personaHandle: 'alice',
    headers: { 'Content-Type': 'application/json' },
    body: '{"ok":true}',
  }, grant)
  assert.equal(aliceDecision.allowed, true)
  assert.equal(aliceDecision.reasonCode, 'allowed_approval_lease')

  const bobDecision = engine.admit({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/projects/40',
    personaHandle: 'bob',
    headers: { 'Content-Type': 'application/json' },
    body: '{"ok":true}',
  }, grant)
  assert.equal(bobDecision.allowed, false, 'RequestAdmissionEngine must deny cross-persona under persona-bound lease')
  assert.equal(bobDecision.reasonCode, 'approval_required')

  // Now opt into crossPersona: true (e.g. BOLA/IDOR differential run).
  const diffAliceCard = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/docs/1',
    personaHandle: 'alice',
    rationale: 'BOLA differential control write',
    requestPreview: '{"name":"v1"}',
    riskLevel: 'medium',
  })
  const diffBobCard = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/docs/2',
    personaHandle: 'bob',
    rationale: 'BOLA differential variant write',
    requestPreview: '{"name":"v2"}',
    riskLevel: 'medium',
  })
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: diffAliceCard.id,
    decision: 'approved',
    scope: 'route',
    crossPersona: true,
    maxUses: 10,
    expiresInMs: 15 * 60_000,
  }))

  assert.equal(store.getApprovalRequest(runId, diffBobCard.id).status, 'approved', 'crossPersona opt-in bulk-approves matching pending card')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'PATCH', '/api/docs/9', 'alice'), true)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'PATCH', '/api/docs/9', 'bob'), true, 'crossPersona opt-in allows Bob')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'PATCH', '/api/docs/9', null), true, 'crossPersona opt-in allows null persona')

  const bobCrossDecision = engine.admit({
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/docs/11',
    personaHandle: 'bob',
    headers: { 'Content-Type': 'application/json' },
    body: '{"name":"v3"}',
  }, grant)
  assert.equal(bobCrossDecision.allowed, true)
  assert.equal(bobCrossDecision.reasonCode, 'allowed_approval_lease')

  // Host non-destructive lease also binds to card persona by default unless crossPersona: true.
  const hostCard = store.createApprovalRequest(store.run(runId), worker, {
    origin: OTHER_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/comments',
    personaHandle: 'alice',
    rationale: 'Host non-destructive write',
    requestPreview: '{"body":"ok"}',
    riskLevel: 'low',
  })
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: hostCard.id,
    decision: 'approved',
    scope: 'host_nondestructive',
  }))
  assert.equal(store.leaseAuthorizes(runId, OTHER_ORIGIN, 'PUT', '/api/profile', 'alice'), true)
  assert.equal(store.leaseAuthorizes(runId, OTHER_ORIGIN, 'PUT', '/api/profile', 'bob'), false, 'host lease must bind to persona by default')
})

test('R2-09 RequestAdmissionEngine rejects structural/destructive R2-01 classifications from durable leases', t => {
  const { store } = makeStore(t)
  const { runId, run } = setupTier3Run(store)

  // Grant permissive cross-persona host + route leases so any rejection MUST come from classification eligibility.
  store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: HOST_NONDESTRUCTIVE_LEASE_METHOD,
    pathAndQuery: HOST_NONDESTRUCTIVE_LEASE_PATTERN,
    leaseScope: 'host_nondestructive',
    crossPersona: true,
  })
  store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/items/42',
    leaseScope: 'route',
    crossPersona: true,
  })
  store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/rpc',
    leaseScope: 'route',
    crossPersona: true,
  })
  store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/graphql',
    leaseScope: 'route',
    crossPersona: true,
  })

  const engine = new RequestAdmissionEngine()
  const grant = {
    tier: 3 as const,
    canRead: (o: string) => o === ORIGIN,
    scopePolicy: store.scopePolicy(runId),
    approvalPolicy: 'auto_review' as const,
    approvalLeases: store.approvalLeaseAuthorizer(runId),
    isStateChangeApproved: () => false,
  }

  // Control: benign POST is allowed by durable lease.
  const benign = engine.admit({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/42',
    headers: { 'Content-Type': 'application/json' },
    body: '{"name":"benign"}',
  }, grant)
  assert.equal(benign.allowed, true)
  assert.equal(benign.reasonCode, 'allowed_approval_lease')

  // 1. Structural mutation (DELETE)
  const delCls = classifyRequestMutation({ origin: ORIGIN, method: 'DELETE', pathAndQuery: '/api/items/42' })
  assert.equal(delCls.isStructuralMutation, true)
  assert.equal(isDurableRouteLeaseEligible(delCls), false)
  const delDecision = engine.admit({ origin: ORIGIN, method: 'DELETE', pathAndQuery: '/api/items/42' }, grant)
  assert.equal(delDecision.allowed, false, 'DELETE structural mutation must never satisfy durable lease')

  // 2. jsonrpc_destructive
  const rpcDestrBody = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'users.deleteAll', params: {} })
  const rpcDestrCls = classifyRequestMutation({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/rpc',
    headers: { 'content-type': 'application/json' },
    body: rpcDestrBody,
  })
  assert.equal(rpcDestrCls.kind, 'jsonrpc_destructive')
  assert.equal(isDurableRouteLeaseEligible(rpcDestrCls), false)
  const rpcDestrDecision = engine.admit({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/rpc',
    headers: { 'Content-Type': 'application/json' },
    body: rpcDestrBody,
  }, grant)
  assert.equal(rpcDestrDecision.allowed, false, 'jsonrpc_destructive must never satisfy durable lease')

  // 3. jsonrpc_malformed
  const rpcMalformedBody = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 123 })
  const rpcMalformedCls = classifyRequestMutation({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/rpc',
    headers: { 'content-type': 'application/json' },
    body: rpcMalformedBody,
  })
  assert.equal(rpcMalformedCls.kind, 'jsonrpc_malformed')
  assert.equal(isDurableRouteLeaseEligible(rpcMalformedCls), false)
  const rpcMalformedDecision = engine.admit({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/rpc',
    headers: { 'Content-Type': 'application/json' },
    body: rpcMalformedBody,
  }, grant)
  assert.equal(rpcMalformedDecision.allowed, false, 'jsonrpc_malformed must never satisfy durable lease')

  // 4. graphql_mutation_or_unverified
  const gqlMutBody = JSON.stringify({ query: 'mutation { updateProfile(name: "qa") { id } }' })
  const gqlCls = classifyRequestMutation({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/graphql',
    headers: { 'content-type': 'application/json' },
    body: gqlMutBody,
  })
  assert.equal(gqlCls.kind, 'graphql_mutation_or_unverified')
  assert.equal(isDurableRouteLeaseEligible(gqlCls), false)
  const gqlDecision = engine.admit({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/graphql',
    headers: { 'Content-Type': 'application/json' },
    body: gqlMutBody,
  }, grant)
  assert.equal(gqlDecision.allowed, false, 'graphql_mutation_or_unverified must never satisfy durable lease')
})

test('R2-09 honest riskLevel audit attribution: bulk route/prefix/host approvals preserve original risk tier (never hardcoded low)', t => {
  const { store } = makeStore(t)
  const { runId, run, worker } = setupTier3Run(store)

  // Route bulk approval preserves 'medium' riskLevel on sibling card.
  const routePrimary = store.createApprovalRequest(run, worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/1',
    rationale: 'Primary medium route write',
    requestPreview: '{"x":1}',
    riskLevel: 'medium',
  })
  const routeSibling = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/2',
    rationale: 'Sibling medium route write',
    requestPreview: '{"x":2}',
    riskLevel: 'medium',
  })
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: routePrimary.id,
    decision: 'approved',
    scope: 'route',
  }))
  assert.equal(store.getApprovalRequest(runId, routeSibling.id).status, 'approved')
  assert.equal(store.getApprovalRequest(runId, routeSibling.id).riskLevel, 'medium', 'route bulk-approval must keep original medium riskLevel')

  // Prefix bulk approval preserves 'medium' riskLevel on sibling card under same prefix.
  const prefixPrimary = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/saveDraft',
    rationale: 'Primary prefix write',
    requestPreview: '{}',
    riskLevel: 'low',
  })
  const prefixSibling = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/publishNote',
    rationale: 'Sibling medium prefix write',
    requestPreview: '{}',
    riskLevel: 'medium',
  })
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: prefixPrimary.id,
    decision: 'approved',
    scope: 'prefix',
  }))
  assert.equal(store.getApprovalRequest(runId, prefixSibling.id).status, 'approved')
  assert.equal(store.getApprovalRequest(runId, prefixSibling.id).riskLevel, 'medium', 'prefix bulk-approval must keep original medium riskLevel')

  // Host non-destructive bulk approval preserves 'medium' riskLevel on sibling card.
  const hostPrimary = store.createApprovalRequest(store.run(runId), worker, {
    origin: OTHER_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/notes',
    rationale: 'Primary host write',
    requestPreview: '{}',
    riskLevel: 'low',
  })
  const hostSibling = store.createApprovalRequest(store.run(runId), worker, {
    origin: OTHER_ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/settings/theme',
    rationale: 'Sibling medium host write',
    requestPreview: '{}',
    riskLevel: 'medium',
  })
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: hostPrimary.id,
    decision: 'approved',
    scope: 'host_nondestructive',
  }))
  assert.equal(store.getApprovalRequest(runId, hostSibling.id).status, 'approved')
  assert.equal(store.getApprovalRequest(runId, hostSibling.id).riskLevel, 'medium', 'host bulk-approval must keep original medium riskLevel')
})

test('R2-09 server-side blast-radius preview computes real endpoint inventory counts, samples, and persona-aware pending counts', t => {
  const { store } = makeStore(t)
  const { runId, run, worker } = setupTier3Run(store)
  const now = Date.now()

  // Seed real discovered endpoint inventory across methods, prefixes, high-risk paths, and origins.
  const seedEndpoint = (origin: string, method: string, pathTemplate: string) => {
    store.db.insert(tables.endpoints).values({
      id: randomUUID(),
      runId,
      scopeRevision: run.scopeRevision,
      origin,
      method,
      pathTemplate,
      source: 'spa_crawl',
      riskScore: 50,
      createdAt: now,
      updatedAt: now,
    }).run()
  }
  seedEndpoint(ORIGIN, 'POST', '/api/v1/users/:id')
  seedEndpoint(ORIGIN, 'POST', '/api/v1/orders/:id')
  seedEndpoint(ORIGIN, 'PATCH', '/api/v1/profile')
  seedEndpoint(ORIGIN, 'DELETE', '/api/v1/users/:id')
  seedEndpoint(ORIGIN, 'POST', '/api/billing/charge')
  seedEndpoint(ORIGIN, 'POST', '/other/action')
  seedEndpoint(OTHER_ORIGIN, 'POST', '/api/v1/users/:id')

  // Seed pending approval cards for Alice and Bob.
  const aliceUsers = store.createApprovalRequest(run, worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/v1/users/42',
    personaHandle: 'alice',
    rationale: 'Alice user update',
    requestPreview: '{}',
    riskLevel: 'medium',
  })
  store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/v1/orders/99',
    personaHandle: 'alice',
    rationale: 'Alice order create',
    requestPreview: '{}',
    riskLevel: 'low',
  })
  store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/v1/users/77',
    personaHandle: 'bob',
    rationale: 'Bob user update (different persona)',
    requestPreview: '{}',
    riskLevel: 'medium',
  })
  store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/v1/profile',
    personaHandle: 'alice',
    rationale: 'Alice profile patch',
    requestPreview: '{}',
    riskLevel: 'low',
  })

  // Default preview (persona-bound to alice).
  const bound = store.runsRepo.previewApprovalBlastRadius(runId, aliceUsers.id)
  assert.equal(bound.once.matchingRouteCount, 1)
  assert.equal(bound.once.pendingApprovalCount, 1)
  assert.equal(bound.once.defaultTtlMs, null)
  assert.equal(bound.once.defaultMaxUses, null)

  assert.equal(bound.route.eligible, true)
  assert.equal(bound.route.pattern, '/api/v1/users/*')
  assert.equal(bound.route.matchingRouteCount, 1)
  assert.deepEqual(bound.route.sampleRoutes, ['POST /api/v1/users/:id'])
  assert.equal(bound.route.pendingApprovalCount, 1, 'persona-bound route preview must exclude Bob pending card')
  assert.equal(bound.route.defaultTtlMs, DEFAULT_APPROVAL_LEASE_TTL_MS)
  assert.equal(bound.route.defaultMaxUses, DEFAULT_ROUTE_LEASE_MAX_USES)
  assert.equal(bound.route.personaHandle, 'alice')
  assert.equal(bound.route.personaBoundByDefault, true)

  assert.equal(bound.prefix.eligible, true)
  assert.equal(bound.prefix.pattern, '/api/v1/**')
  assert.equal(bound.prefix.matchingRouteCount, 2, 'POST under /api/v1/** matches users + orders only')
  assert.deepEqual(bound.prefix.sampleRoutes.sort(), ['POST /api/v1/orders/:id', 'POST /api/v1/users/:id'])
  assert.equal(bound.prefix.pendingApprovalCount, 2, 'Alice users + Alice orders under /api/v1/**')
  assert.equal(bound.prefix.defaultMaxUses, DEFAULT_PREFIX_LEASE_MAX_USES)

  assert.equal(bound.host_nondestructive.eligible, true)
  assert.equal(
    bound.host_nondestructive.matchingRouteCount,
    4,
    'host_nondestructive matches POST users, POST orders, PATCH profile, POST /other/action (excludes DELETE, billing, other origin)',
  )
  assert.equal(bound.host_nondestructive.sampleRoutes.some(r => r.includes('DELETE') || r.includes('billing')), false)
  assert.equal(bound.host_nondestructive.pendingApprovalCount, 3, 'Alice users + Alice orders + Alice profile')
  assert.equal(bound.host_nondestructive.defaultMaxUses, DEFAULT_HOST_LEASE_MAX_USES)

  // Cross-persona preview includes Bob's matching pending card.
  const cross = store.runsRepo.previewApprovalBlastRadius(runId, aliceUsers.id, { crossPersona: true })
  assert.equal(cross.route.pendingApprovalCount, 2, 'cross-persona route preview includes Bob pending card')
  assert.equal(cross.prefix.pendingApprovalCount, 3, 'cross-persona prefix preview includes Bob pending card')
  assert.equal(cross.host_nondestructive.pendingApprovalCount, 4, 'cross-persona host preview includes Bob pending card')
})
