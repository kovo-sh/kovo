import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { newProject, newRun } from '../src/domain.ts'
import type { Finding } from '../src/domain.ts'
import { MAX_STORED_OOB_REJECTIONS, OobRelay } from '../src/server/oob-relay.ts'
import {
  SQLITE_DEFAULT_BUSY_TIMEOUT_MS,
  SQLITE_JOURNAL_SIZE_LIMIT_BYTES,
  artifactBucket,
  tenantBlobFile,
} from '../src/server/store-session.ts'
import { Store, TenantIsolationError } from '../src/server/store.ts'

function withTempStore(
  t: test.TestContext,
  fn: (ctx: { dir: string; store: Store }) => void | Promise<void>,
) {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-arch-s1s2-'))
  const store = new Store(dir)
  t.after(() => {
    store.close()
    rmSync(dir, { recursive: true, force: true })
  })
  return fn({ dir, store })
}

function makeProjectAndRun(store: Store, name: string, origin: string, tenantId?: string) {
  const proj = store.createProject(newProject.parse({
    requestId: randomUUID(),
    name,
    environment: 'public',
    seeds: [origin],
  }))
  if (tenantId) {
    store.setProjectTenant(proj.id, tenantId)
  }
  const createdRun = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: proj.id,
    goal: `Assess ${name}`,
    capabilityTier: 1,
  }))
  store.command({ requestId: randomUUID(), runId: createdRun.id, action: 'discover', consent: true })
  const discovered = store.run(createdRun.id)
  store.command({
    requestId: randomUUID(),
    runId: createdRun.id,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    saveProject: true,
    capabilityTier: 1,
  })
  const run = store.run(createdRun.id)
  const worker = store.makeWorker(run, 'investigation', run.candidates[0], 'Inspect', 'Verify controls')
  return { projectId: proj.id, runId: run.id, run, worker }
}

test('S1: non-default tenant run creation persists project tenantId and never leaks into default tenant', t =>
  withTempStore(t, ({ store }) => {
    const defaultProj = store.createProject(newProject.parse({
      requestId: randomUUID(),
      name: 'Default App',
      environment: 'public',
      seeds: ['https://default.example.test'],
    }))
    const defaultRun = store.createRun(newRun.parse({
      requestId: randomUUID(),
      projectId: defaultProj.id,
      goal: 'Default run',
      capabilityTier: 1,
    }))

    const alphaProj = store.createProject(newProject.parse({
      requestId: randomUUID(),
      name: 'Alpha App',
      environment: 'public',
      seeds: ['https://alpha.example.test'],
    }))
    store.setProjectTenant(alphaProj.id, 'tenant-alpha')
    const alphaRun = store.createRun(newRun.parse({
      requestId: randomUUID(),
      projectId: alphaProj.id,
      goal: 'Alpha run created after tenant assignment',
      capabilityTier: 1,
    }))

    // Persisted SQL column must store 'tenant-alpha' directly, never silently 'default'.
    const rawRow = store.client.prepare('SELECT tenant_id FROM runs WHERE id = ?').get(alphaRun.id) as { tenant_id: string }
    assert.equal(rawRow.tenant_id, 'tenant-alpha')
    assert.equal(store.getRunTenant(alphaRun.id), 'tenant-alpha')

    // listRunsForTenant('default') must NEVER return tenant-alpha's run.
    assert.deepEqual(store.listRunsForTenant('default').map(r => r.id), [defaultRun.id])
    assert.deepEqual(store.listRunsForTenant('tenant-alpha').map(r => r.id), [alphaRun.id])

    // Even if a legacy pre-fix row has runs.tenant_id = 'default' under a tenant-alpha project,
    // COALESCE(NULLIF(r.tenant_id, 'default'), p.tenant_id, 'default') still isolates it from 'default'.
    store.client.prepare("UPDATE runs SET tenant_id = 'default' WHERE id = ?").run(alphaRun.id)
    assert.deepEqual(store.listRunsForTenant('default').map(r => r.id), [defaultRun.id])
    assert.deepEqual(store.listRunsForTenant('tenant-alpha').map(r => r.id), [alphaRun.id])

    // setProjectTenant atomically updates both projects and all child runs.
    store.setProjectTenant(alphaProj.id, 'tenant-beta')
    const projTenantRow = store.client.prepare('SELECT tenant_id FROM projects WHERE id = ?').get(alphaProj.id) as { tenant_id: string }
    const runTenantRow = store.client.prepare('SELECT tenant_id FROM runs WHERE id = ?').get(alphaRun.id) as { tenant_id: string }
    assert.equal(projTenantRow.tenant_id, 'tenant-beta')
    assert.equal(runTenantRow.tenant_id, 'tenant-beta')
    assert.deepEqual(store.listRunsForTenant('tenant-alpha'), [])
    assert.deepEqual(store.listRunsForTenant('tenant-beta').map(r => r.id), [alphaRun.id])

    // getProjectTenant & listProjectsForTenant scope strictly by workspace_id.
    const foreignWsId = randomUUID()
    const foreignProjId = randomUUID()
    store.client.prepare(
      'INSERT INTO workspaces (id, name, actor_id, created_at) VALUES (?, ?, ?, ?)',
    ).run(foreignWsId, 'Foreign WS', randomUUID(), Date.now())
    store.client.prepare(
      `INSERT INTO projects (id, workspace_id, tenant_id, name, environment, seeds, default_scope, sandbox_write_allowlist, created_at)
       VALUES (?, ?, ?, 'Foreign Proj', 'public', '["https://foreign.example.test"]', '["https://foreign.example.test"]', '[]', ?)`,
    ).run(foreignProjId, foreignWsId, 'tenant-beta', Date.now())
    assert.throws(() => store.getProjectTenant(foreignProjId), /Unknown project/)
    assert.deepEqual(store.listProjectsForTenant('tenant-beta').map(p => p.id), [alphaProj.id])
  }))

test('S1: store.forTenant(tenantId) enforces strict repository boundary across reads, writes, and child IDs', t =>
  withTempStore(t, ({ store }) => {
    const tenantA = store.forTenant('tenant-a')
    const tenantB = store.forTenant('tenant-b')
    const defaultScope = store.forTenant('default')

    const projA = tenantA.createProject(newProject.parse({
      requestId: randomUUID(),
      name: 'Tenant A Portal',
      environment: 'public',
      seeds: ['https://a.example.test'],
    }))
    const projB = tenantB.createProject(newProject.parse({
      requestId: randomUUID(),
      name: 'Tenant B Portal',
      environment: 'public',
      seeds: ['https://b.example.test'],
    }))
    const projDefault = store.createProject(newProject.parse({
      requestId: randomUUID(),
      name: 'Desktop Single-Tenant App',
      environment: 'public',
      seeds: ['https://cli.example.test'],
    }))

    assert.equal(tenantA.getProjectTenant(projA.id), 'tenant-a')
    assert.equal(tenantB.getProjectTenant(projB.id), 'tenant-b')
    assert.equal(defaultScope.getProjectTenant(projDefault.id), 'default')

    const runARef = tenantA.createRun(newRun.parse({
      requestId: randomUUID(),
      projectId: projA.id,
      goal: 'Audit Tenant A',
      capabilityTier: 1,
    }))
    tenantA.command({ requestId: randomUUID(), runId: runARef.id, action: 'discover', consent: true })
    const discA = tenantA.run(runARef.id)
    tenantA.command({
      requestId: randomUUID(),
      runId: runARef.id,
      action: 'scope',
      assetIds: discA.candidates.map(c => c.id),
      expectedScopeRevision: discA.scopeRevision,
      consent: true,
      saveProject: true,
      capabilityTier: 1,
    })
    const runA = tenantA.run(runARef.id)
    const workerA = tenantA.makeWorker(runA, 'investigation', runA.candidates[0], 'Worker A', 'Inspect A')
    const stepA = tenantA.addChainStep(runA, {
      title: 'Step A',
      hypothesis: 'Check access controls',
      targetAssetIds: [runA.candidates[0]!.id],
    })
    const approvalA = tenantA.createApprovalRequest(runA, workerA, {
      origin: 'https://a.example.test',
      method: 'POST',
      pathAndQuery: '/api/items',
      rationale: 'Verify state transition',
      requestPreview: 'POST /api/items',
    })
    const exA = tenantA.recordExchange({
      runId: runA.id,
      assignmentId: workerA.id,
      scopeRevision: runA.scopeRevision,
      origin: 'https://a.example.test',
      finalOrigin: 'https://a.example.test',
      redirectOrigins: [],
      method: 'GET',
      pathAndQuery: '/api/secret-a',
      status: 200,
      mediaType: 'application/json',
      reqHeaders: {},
      respHeaders: {},
      body: '{"tenant":"alpha-only-payload"}',
      durationMs: 12,
    })
    const findingA: Finding = {
      id: randomUUID(),
      origin: 'https://a.example.test',
      title: 'Tenant A Proposed Finding',
      status: 'pending',
      severity: 'medium',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      reason: 'Proposed access issue',
      remediation: 'Enforce ownership checks',
      evidenceIds: [],
      exchangeIds: [exA.id],
      scopeRevision: runA.scopeRevision,
    }
    const specA = tenantA.createReplaySpec(runA, workerA, findingA.id, {
      version: 1,
      kind: 'http_chain',
      origin: 'https://a.example.test',
      title: findingA.title,
      category: 'broken-access-control',
      cwe: 'CWE-639',
      severity: 'medium',
      severityRationale: 'Cross-account read',
      impact: 'Unauthorized disclosure',
      remediation: 'Enforce ownership checks',
      recheckInstructions: 'Replay request',
      assertionsJq: '.status == 200',
      spaCatchallControl: false,
      steps: [{
        id: 'probe-1',
        role: 'probe',
        description: 'Fetch secret endpoint',
        request: {
          origin: 'https://a.example.test',
          method: 'GET',
          pathAndQuery: '/api/secret-a',
          followRedirects: false,
        },
      }],
    }, ['https://a.example.test'])
    tenantA.upsertChainFinding(runA, runA.candidates[0]!.id, findingA, specA.id, ['https://a.example.test'])

    // Dashboard & listing views only surface the caller's own tenant.
    assert.deepEqual(tenantA.listWorkspace().projects.map(p => p.id), [projA.id])
    assert.deepEqual(tenantB.listWorkspace().projects.map(p => p.id), [projB.id])
    assert.deepEqual(defaultScope.listWorkspace().projects.map(p => p.id), [projDefault.id])
    assert.deepEqual(tenantA.workspaceSummary().recentRuns.map(r => r.id), [runA.id])
    assert.deepEqual(tenantB.workspaceSummary().recentRuns, [])
    assert.deepEqual(tenantA.runShellSummary(runA.id).runs.map(r => r.id), [runA.id])

    // Every cross-tenant read/write/child-ID operation from Tenant B fails closed with TenantIsolationError.
    const expectDenied = (fn: () => unknown, label: string) => {
      assert.throws(
        fn,
        (err: unknown) => err instanceof TenantIsolationError && err.code === 'TENANT_ISOLATION_DENIED',
        `Expected TenantIsolationError for ${label}`,
      )
    }

    expectDenied(() => tenantB.project(projA.id), 'project')
    expectDenied(() => tenantB.projectDetail(projA.id), 'projectDetail')
    expectDenied(() => tenantB.run(runA.id), 'run')
    expectDenied(() => tenantB.runDetail(runA.id), 'runDetail')
    expectDenied(() => tenantB.runShellSummary(runA.id), 'runShellSummary')
    expectDenied(() => tenantB.updateRun(runA.id, { phase: 'complete' }), 'updateRun')
    expectDenied(() => tenantB.updateWorker(workerA.id, { status: 'canceled' }), 'updateWorker')
    expectDenied(() => tenantB.updateChainStep(stepA.id, { status: 'canceled' }), 'updateChainStep')
    expectDenied(() => tenantB.listBoardMessages(runA.id), 'listBoardMessages')
    expectDenied(() => tenantB.getApprovalRequest(runA.id, approvalA.id), 'getApprovalRequest')
    expectDenied(() => tenantB.getExchange(runA.id, exA.id), 'getExchange')
    expectDenied(() => tenantB.searchExchanges(runA.id, 'alpha'), 'searchExchanges')
    expectDenied(() => tenantB.triageFinding(findingA.id, { status: 'false_positive' }), 'triageFinding')
    expectDenied(() => tenantB.deleteRun(runA.id), 'deleteRun')
    expectDenied(() => tenantB.deleteProject(projA.id), 'deleteProject')
    expectDenied(() => tenantB.createRun(newRun.parse({
      requestId: randomUUID(),
      projectId: projA.id,
      goal: 'Cross-tenant hijack attempt',
      capabilityTier: 1,
    })), 'createRun on foreign project')
  }))

test('S1: tenant-partitioned blobs isolate Tenant A from Tenant B without cross-tenant directory scans', t =>
  withTempStore(t, ({ dir, store }) => {
    const a = makeProjectAndRun(store, 'Blob Tenant A', 'https://blob-a.example.test', 'tenant-a')
    const b = makeProjectAndRun(store, 'Blob Tenant B', 'https://blob-b.example.test', 'tenant-b')

    const bodyA = '{"secretView":"tenant-a-confidential-body-9182"}'
    const sharedBody = '{"shared":"identical-body-in-both-tenants"}'

    const exA = store.recordExchange({
      runId: a.runId,
      assignmentId: a.worker.id,
      scopeRevision: a.run.scopeRevision,
      origin: 'https://blob-a.example.test',
      finalOrigin: 'https://blob-a.example.test',
      redirectOrigins: [],
      method: 'GET',
      pathAndQuery: '/private',
      status: 200,
      mediaType: 'application/json',
      reqHeaders: {},
      respHeaders: {},
      body: bodyA,
      durationMs: 10,
    })
    const exSharedA = store.recordExchange({
      runId: a.runId,
      assignmentId: a.worker.id,
      scopeRevision: a.run.scopeRevision,
      origin: 'https://blob-a.example.test',
      finalOrigin: 'https://blob-a.example.test',
      redirectOrigins: [],
      method: 'GET',
      pathAndQuery: '/shared',
      status: 200,
      mediaType: 'application/json',
      reqHeaders: {},
      respHeaders: {},
      body: sharedBody,
      durationMs: 10,
    })
    const exSharedB = store.recordExchange({
      runId: b.runId,
      assignmentId: b.worker.id,
      scopeRevision: b.run.scopeRevision,
      origin: 'https://blob-b.example.test',
      finalOrigin: 'https://blob-b.example.test',
      redirectOrigins: [],
      method: 'GET',
      pathAndQuery: '/shared',
      status: 200,
      mediaType: 'application/json',
      reqHeaders: {},
      respHeaders: {},
      body: sharedBody,
      durationMs: 10,
    })
    store.flushNow()

    assert.ok(exA.bodyArtifactId)
    assert.ok(exSharedA.bodyArtifactId)
    assert.equal(exSharedA.bodyArtifactId, exSharedB.bodyArtifactId)

    // Newly written non-default tenant blobs live strictly under artifacts/<tenantId>/blobs/<bucket>/.
    const expectedPathA = tenantBlobFile(dir, 'tenant-a', exA.bodyArtifactId)
    const expectedBucketA = artifactBucket(exA.bodyArtifactId)
    assert.equal(expectedPathA, join(dir, 'artifacts', 'tenant-a', 'blobs', expectedBucketA, `${exA.bodyArtifactId}.txt`))
    assert.equal(existsSync(expectedPathA), true, 'tenant-a blob must be stored under artifacts/tenant-a/blobs/<bucket>/')
    assert.equal(existsSync(join(dir, 'artifacts', `${exA.bodyArtifactId}.txt`)), false, 'must not write flat blob')
    assert.equal(existsSync(join(dir, 'artifacts', a.runId, 'blobs', expectedBucketA, `${exA.bodyArtifactId}.txt`)), false)

    // Tenant A can read its own blob.
    assert.equal(store.forTenant('tenant-a').readBlob(exA.bodyArtifactId), bodyA)
    assert.equal(store.readBlob(exA.bodyArtifactId, a.runId), bodyA)

    // Tenant B (and unscoped default) must NEVER traverse Tenant A's directory to read Tenant A's blob.
    assert.throws(() => store.forTenant('tenant-b').readBlob(exA.bodyArtifactId!), /Artifact not found/)
    assert.throws(() => store.readBlob(exA.bodyArtifactId!, b.runId), /Artifact not found/)
    assert.throws(() => store.readBlob(exA.bodyArtifactId!), /Artifact not found/)
    assert.throws(
      () => store.readBlob(exA.bodyArtifactId!, a.runId, 'tenant-b'),
      (err: unknown) => err instanceof TenantIsolationError,
    )

    // Pruning Tenant A's shared blob removes ONLY Tenant A's partition copy, leaving Tenant B intact.
    const sharedPathA = tenantBlobFile(dir, 'tenant-a', exSharedA.bodyArtifactId)
    const sharedPathB = tenantBlobFile(dir, 'tenant-b', exSharedB.bodyArtifactId!)
    assert.equal(existsSync(sharedPathA), true)
    assert.equal(existsSync(sharedPathB), true)
    store.client.prepare('UPDATE broker_exchanges SET created_at = ? WHERE run_id = ?').run(Date.now() - 120_000, a.runId)
    const pruned = store.pruneExchanges({ runId: a.runId, olderThanMs: 60_000 })
    assert.equal(pruned.blobs, 2)
    assert.equal(existsSync(sharedPathA), false, 'Tenant A blob removed after pruning Tenant A')
    assert.equal(existsSync(sharedPathB), true, 'Tenant B blob must remain untouched')
    assert.equal(store.forTenant('tenant-b').readBlob(exSharedB.bodyArtifactId!), sharedBody)

    // Legacy flat path migration fallback still works for default tenant when not owned by another tenant.
    const legacyId = 'blob-' + 'a'.repeat(64)
    writeFileSync(join(dir, 'artifacts', `${legacyId}.txt`), 'legacy-flat-content', { mode: 0o600 })
    assert.equal(store.readBlob(legacyId), 'legacy-flat-content')
  }))

test('S2: concurrent appendTenantAuditLog preserves unbroken hash chain and enforces UNIQUE(tenant_id, prev_hash)', async t =>
  withTempStore(t, async ({ dir, store }) => {
    const entries = await Promise.all(
      Array.from({ length: 40 }, (_, i) =>
        Promise.resolve().then(() =>
          store.appendTenantAuditLog({
            tenantId: 'tenant-chain',
            actor: `worker-${i % 4}`,
            action: `event.${i}`,
            resourceKind: 'run',
            resourceId: `run-${i}`,
            outcome: 'allowed',
            detail: { idx: i },
          }),
        ),
      ),
    )
    assert.equal(entries.length, 40)
    const verified = store.verifyTenantAuditLogChain('tenant-chain')
    assert.deepEqual(verified, { valid: true, count: 40 })

    // Verify DB-level UNIQUE(tenant_id, prev_hash) prevents external fork attempts.
    const external = new DatabaseSync(join(dir, 'kovo.sqlite'), { timeout: 5_000 })
    try {
      const latest = external.prepare(
        "SELECT prev_hash FROM tenant_audit_log WHERE tenant_id = 'tenant-chain' ORDER BY seq DESC LIMIT 1",
      ).get() as { prev_hash: string }
      assert.throws(() => {
        external.prepare(
          `INSERT INTO tenant_audit_log
           (id, tenant_id, run_id, actor, action, resource_kind, resource_id, outcome, detail, prev_hash, entry_hash, created_at)
           VALUES (?, 'tenant-chain', NULL, 'rogue', 'fork', 'run', NULL, 'denied', '{}', ?, ?, ?)`,
        ).run(randomUUID(), latest.prev_hash, 'f'.repeat(64), Date.now())
      }, /UNIQUE constraint failed/)
    } finally {
      external.close()
    }
    assert.deepEqual(store.verifyTenantAuditLogChain('tenant-chain'), { valid: true, count: 40 })
  }))

test('S2: concurrent suggestCandidateHost, addChainStep, triageFinding, updateProposedFinding & atomic counters never lose updates', async t =>
  withTempStore(t, async ({ store }) => {
    const { runId, run, worker } = makeProjectAndRun(store, 'Concurrency App', 'https://conc.example.test')
    // Capture ONE stale run snapshot shared across concurrent workers.
    const staleRun = store.run(runId)

    // 1. Concurrent suggestCandidateHost with stale run snapshot must preserve ALL suggested hosts.
    const hosts = Array.from({ length: 8 }, (_, i) => `https://sub${i}.conc.example.test`)
    const suggestResults = await Promise.all(
      hosts.map((origin, i) =>
        Promise.resolve().then(() => store.suggestCandidateHost(staleRun, origin, `worker-${i}`)),
      ),
    )
    assert.equal(suggestResults.filter(r => r.added).length, hosts.length)
    const updatedRun = store.run(runId)
    for (const origin of hosts) {
      assert.ok(updatedRun.candidates.some(c => c.origin === origin), `Lost candidate ${origin}`)
    }

    // 2. Concurrent addChainStep assigns strictly unique sequential seq numbers.
    const steps = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        Promise.resolve().then(() =>
          store.addChainStep(staleRun, {
            title: `Concurrent Step ${i}`,
            hypothesis: `Test hypothesis ${i}`,
            targetAssetIds: [staleRun.candidates[0]!.id],
          }),
        ),
      ),
    )
    const seqs = steps.map(s => s.seq).sort((a, b) => a - b)
    assert.deepEqual(seqs, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

    // 3. Concurrent triageFinding calls preserve disjoint fields (status, severityOverride, notes).
    const findingId = randomUUID()
    const spec = store.createReplaySpec(run, worker, findingId, {
      version: 1,
      kind: 'http_chain',
      origin: 'https://conc.example.test',
      title: 'Concurrent Finding',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      severity: 'medium',
      severityRationale: 'Access boundary',
      impact: 'Unauthorized access',
      remediation: 'Check ownership',
      recheckInstructions: 'Replay request',
      assertionsJq: '.status == 200',
      spaCatchallControl: false,
      steps: [{
        id: 'probe-1',
        role: 'probe',
        description: 'Fetch item 1',
        request: {
          origin: 'https://conc.example.test',
          method: 'GET',
          pathAndQuery: '/api/items/1',
          followRedirects: false,
        },
      }],
    }, ['https://conc.example.test'])
    store.upsertChainFinding(run, run.candidates[0]!.id, {
      id: findingId,
      origin: 'https://conc.example.test',
      title: 'Concurrent Finding',
      status: 'pending',
      severity: 'medium',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      reason: 'Initial hypothesis',
      remediation: 'Check ownership',
      evidenceIds: ['ev-0'],
      exchangeIds: ['ex-0'],
      scopeRevision: run.scopeRevision,
    }, spec.id, ['https://conc.example.test'])

    await Promise.all([
      Promise.resolve().then(() => store.findingsRepo.triageFinding(findingId, { status: 'confirmed_by_operator' })),
      Promise.resolve().then(() => store.findingsRepo.triageFinding(findingId, { severityOverride: 'high' })),
      Promise.resolve().then(() => store.findingsRepo.triageFinding(findingId, { notes: 'Reviewed by analyst team' })),
    ])
    const triagedRow = store.runDetail(runId).findings.find(f => f.id === findingId) as (Finding & {
      operatorTriage?: { status: string; severityOverride: string | null; notes: string }
    }) | undefined
    assert.equal(triagedRow?.operatorTriage?.status, 'confirmed_by_operator')
    assert.equal(triagedRow?.operatorTriage?.severityOverride, 'high')
    assert.equal(triagedRow?.operatorTriage?.notes, 'Reviewed by analyst team')

    // 4. Concurrent updateProposedFinding merges evidenceIds/exchangeIds/chainFactIds without losing updates or operatorTriage.
    await Promise.all([
      Promise.resolve().then(() => store.updateProposedFinding(staleRun, findingId, {
        finding: { evidenceIds: ['ev-1'], exchangeIds: ['ex-1'] },
        counterevidence: 'Checked header variants',
      })),
      Promise.resolve().then(() => store.updateProposedFinding(staleRun, findingId, {
        finding: { evidenceIds: ['ev-2'], chainFactIds: ['fact-2'] },
        confidenceRationale: 'Consistent differential behavior',
      })),
      Promise.resolve().then(() => store.updateProposedFinding(staleRun, findingId, {
        finding: { exchangeIds: ['ex-3'], chainFactIds: ['fact-3'] },
      })),
    ])
    const merged = store.runDetail(runId).findings.find(f => f.id === findingId) as (Finding & {
      operatorTriage?: { status: string; severityOverride: string | null; notes: string }
    }) | undefined
    assert.ok(merged)
    for (const id of ['ev-0', 'ev-1', 'ev-2']) assert.ok(merged.evidenceIds.includes(id), `Missing ${id}`)
    for (const id of ['ex-0', 'ex-1', 'ex-3']) assert.ok(merged.exchangeIds?.includes(id), `Missing ${id}`)
    for (const id of ['fact-2', 'fact-3']) assert.ok(merged.chainFactIds?.includes(id), `Missing ${id}`)
    assert.equal(merged.counterevidence, 'Checked header variants')
    assert.equal(merged.confidenceRationale, 'Consistent differential behavior')
    assert.equal(merged.operatorTriage?.status, 'confirmed_by_operator', 'operatorTriage must survive updateProposedFinding')

    // 5. SQL-atomic counters: leaseAuthorizes uses & boardMembers postsCount.
    store.grantApprovalLease(staleRun, {
      origin: 'https://conc.example.test',
      method: 'POST',
      pathAndQuery: '/api/orders/1',
    })
    for (let i = 0; i < 5; i += 1) {
      assert.equal(store.leaseAuthorizes(runId, 'https://conc.example.test', 'POST', `/api/orders/${i + 10}`), true)
    }
    const lease = store.listApprovalLeases(runId, 'active')[0]
    assert.equal(lease?.uses, 5)

    for (let i = 0; i < 4; i += 1) {
      store.postBoardMessage(staleRun, {
        authorHandle: 'coordinator',
        authorRole: 'coordinator',
        kind: 'note',
        body: `Progress note ${i}`,
      })
    }
    assert.equal(store.boardMember(runId, 'coordinator')?.postsCount, 4)
  }))

test('S2: SQLite connection pragmas (WAL, busy_timeout=5000, journal_size_limit=64MiB) & oob_rejections bounded cap', t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-arch-s2-pragmas-'))
  const store = new Store(dir)
  const relay = new OobRelay({ directory: dir })
  const smallCapDir = mkdtempSync(join(tmpdir(), 'kovo-arch-s2-oobcap-'))
  const smallCapRelay = new OobRelay({ directory: smallCapDir, maxRejections: 25 })
  t.after(() => {
    smallCapRelay.close()
    relay.close()
    store.close()
    rmSync(smallCapDir, { recursive: true, force: true })
    rmSync(dir, { recursive: true, force: true })
  })

  // Verify Store SQLite pragmas.
  const storeJournal = store.client.prepare('PRAGMA journal_mode').get() as { journal_mode: string }
  const storeBusy = store.client.prepare('PRAGMA busy_timeout').get() as { timeout: number }
  const storeLimit = store.client.prepare('PRAGMA journal_size_limit').get() as { journal_size_limit: number }
  assert.equal(storeJournal.journal_mode.toLowerCase(), 'wal')
  assert.equal(Number(storeBusy.timeout), SQLITE_DEFAULT_BUSY_TIMEOUT_MS)
  assert.equal(Number(storeLimit.journal_size_limit), SQLITE_JOURNAL_SIZE_LIMIT_BYTES)
  assert.equal(SQLITE_JOURNAL_SIZE_LIMIT_BYTES, 67_108_864)

  // Verify OobRelay SQLite pragmas on disk.
  const oobCheck = new DatabaseSync(join(dir, 'oob-relay.sqlite'), { readOnly: true })
  try {
    const oobJournal = oobCheck.prepare('PRAGMA journal_mode').get() as { journal_mode: string }
    assert.equal(oobJournal.journal_mode.toLowerCase(), 'wal')
  } finally {
    oobCheck.close()
  }

  // Verify bounded cap on custom maxRejections = 25 (oldest rows evicted, newest 25 retained).
  for (let i = 0; i < 60; i += 1) {
    const res = smallCapRelay.recordCallback({
      token: `invalid-spam-${i}`,
      callbackId: `cb-small-${i}`,
      sourceIp: '203.0.113.9',
    })
    assert.equal(res.accepted, false)
  }
  assert.equal(smallCapRelay.status().rejected, 25)
  const latestSmall = smallCapRelay.rejections(50)
  assert.equal(latestSmall.length, 25)
  assert.equal(latestSmall[0]?.callbackId, 'cb-small-59')
  assert.equal(latestSmall[24]?.callbackId, 'cb-small-35')

  // Verify default MAX_STORED_OOB_REJECTIONS = 5,000 cap under >5,000 spam events.
  assert.equal(MAX_STORED_OOB_REJECTIONS, 5_000)
  for (let i = 0; i < MAX_STORED_OOB_REJECTIONS + 150; i += 1) {
    relay.recordCallback({
      token: 'not-a-valid-token',
      callbackId: `cb-flood-${i}`,
      sourceIp: '198.51.100.42',
    })
  }
  assert.equal(relay.status().rejected, MAX_STORED_OOB_REJECTIONS)
  const latestDefault = relay.rejections(5)
  assert.equal(latestDefault[0]?.callbackId, `cb-flood-${MAX_STORED_OOB_REJECTIONS + 149}`)
})
