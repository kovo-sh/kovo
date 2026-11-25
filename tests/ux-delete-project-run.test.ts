import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { newRun } from '../src/domain.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import {
  Store,
  deleteProjectWithActiveGuard,
  deleteRunWithActiveGuard,
} from '../src/server/store.ts'
import * as tables from '../src/server/schema.ts'

function withTempStore(fn: (ctx: { dir: string; store: Store }) => Promise<void> | void) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), 'guardian-ux-del-'))
    const store = new Store(dir, { ftsMode: 'preview' })
    try {
      await fn({ dir, store })
    } finally {
      store.close()
      rmSync(dir, { recursive: true, force: true })
    }
  }
}

function seedFullRunGraph(store: Store, dir: string, projectId: string, origin: string) {
  const run = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId,
    goal: 'Audit full target surface',
    capabilityTier: 2,
  }))
  const now = Date.now()
  const sessionId = `sess-${randomUUID()}`
  const assignmentId = randomUUID()

  store.db.insert(tables.assignments).values({
    id: assignmentId,
    runId: run.id,
    phase: 'investigation',
    status: 'complete',
    scopeRevision: 1,
    goalRevision: 1,
    sessionId,
    parentFactIds: [],
    sourceOrigins: [origin],
    title: 'Investigate target',
    objective: 'Check endpoints',
    createdAt: now,
  }).run()

  const factId = randomUUID()
  store.db.insert(tables.facts).values({
    id: factId,
    runId: run.id,
    assignmentId,
    scopeRevision: 1,
    goalRevision: 1,
    kind: 'endpoint',
    origin,
    summary: 'Found /api/items',
    data: {},
    sourceOrigins: [origin],
    evidenceIds: [],
    exchangeIds: [],
    createdAt: now,
  }).run()

  store.db.insert(tables.graphEdges).values({
    id: randomUUID(),
    runId: run.id,
    fromKind: 'assignment',
    fromId: assignmentId,
    toKind: 'fact',
    toId: factId,
    edgeKind: 'yields',
    createdAt: now,
  }).run()

  store.db.insert(tables.graphDigests).values({
    id: randomUUID(),
    runId: run.id,
    roundNo: 1,
    level: 'minor',
    signatureHash: `sig-${randomUUID()}`,
    summary: 'Round 1 digest',
    coveredFactIds: [factId],
    coveredAssignmentIds: [assignmentId],
    createdAt: now,
  }).run()

  store.db.insert(tables.threatModels).values({
    id: randomUUID(),
    runId: run.id,
    scopeRevision: 1,
    goalRevision: 1,
    entries: [],
    summary: 'Threat model',
    createdAt: now,
  }).run()

  store.db.insert(tables.chainSteps).values({
    id: randomUUID(),
    runId: run.id,
    goalRevision: 1,
    scopeRevision: 1,
    seq: 1,
    title: 'Check auth',
    hypothesis: 'Cross-user read',
    targetAssetIds: [],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    status: 'complete',
    sourceOrigins: [origin],
    createdAt: now,
    updatedAt: now,
  }).run()

  const exchangeId = randomUUID()
  const bodyArtifactId = `blob-${randomUUID()}`
  store.db.insert(tables.brokerExchanges).values({
    id: exchangeId,
    runId: run.id,
    assignmentId,
    scopeRevision: 1,
    origin,
    finalOrigin: origin,
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery: '/api/items',
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: {},
    bodyPreview: '{"ok":true}',
    bodyArtifactId,
    bodySha256: 'deadbeef',
    secretMatches: [],
    durationMs: 12,
    createdAt: now,
  }).run()
  store.client.prepare(
    `INSERT INTO broker_exchanges_fts (exchange_id, run_id, origin, method, path_and_query, req_headers, resp_headers, body_preview)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(exchangeId, run.id, origin, 'GET', '/api/items', '{}', '{}', '{"ok":true}')

  store.db.insert(tables.approvalRequests).values({
    id: randomUUID(),
    runId: run.id,
    assignmentId,
    scopeRevision: 1,
    origin,
    method: 'POST',
    pathAndQuery: '/api/items',
    rationale: 'Verify write path',
    requestPreview: 'POST /api/items',
    status: 'denied',
    expiresAt: now + 60_000,
    createdAt: now,
  }).run()

  store.db.insert(tables.approvalLeases).values({
    id: randomUUID(),
    runId: run.id,
    scopeRevision: 1,
    origin,
    method: 'POST',
    routePattern: '/api/items',
    status: 'revoked',
    createdBy: 'operator',
    createdAt: now,
    updatedAt: now,
  }).run()

  const evidenceId = randomUUID()
  store.db.insert(tables.evidence).values({
    id: evidenceId,
    runId: run.id,
    assignmentId,
    scopeRevision: 1,
    goalRevision: 1,
    title: 'Proof capture',
    kind: 'exchange',
    createdAt: now,
  }).run()

  const findingId = randomUUID()
  const replaySpecId = randomUUID()
  store.db.insert(tables.replaySpecs).values({
    id: replaySpecId,
    runId: run.id,
    findingId,
    assignmentId,
    scopeRevision: 1,
    goalRevision: 1,
    spec: {
      version: 1,
      vulnClass: 'bola',
      steps: [],
      assertions: [],
    } as never,
    specSha256: 'abc123',
    sourceOrigins: [origin],
    verifiedInline: true,
    lastVerificationDiff: { verdict: 'confirmed' } as never,
    proofKind: 'agent_script',
    proofVerdict: 'confirmed',
    proofReceipt: {
      receipt: {
        vulnClass: 'bola',
        target: { origin },
        exchangeIds: [exchangeId],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'cross-tenant read',
      },
      verification: {
        confirmed: true,
        vulnClass: 'bola',
        rule: 'bola',
        reason: 'verified',
        observed: '200',
        expected: '403',
      },
    },
    createdAt: now,
  }).run()

  store.db.insert(tables.retestRuns).values({
    id: randomUUID(),
    projectId,
    runId: run.id,
    findingId,
    replaySpecId,
    scopeRevision: 1,
    verdict: 'reproduced',
    summary: 'Reproduced',
    evidenceIds: [evidenceId],
    exchangeIds: [exchangeId],
    createdAt: now,
  }).run()

  store.db.insert(tables.findings).values({
    id: findingId,
    runId: run.id,
    assetId: origin,
    goalRevision: 1,
    checkId: 'chain',
    caseId: 'case-1',
    findingKind: 'multi_step_chain',
    replaySpecId,
    provenance: 'agent_only',
    verificationClass: 'runtime_confirmed',
    sourceOrigins: [origin],
    finding: {
      id: findingId,
      title: 'Cross-account access',
      severity: 'high',
      status: 'confirmed',
      summary: 'Confirmed cross-account read',
      remediation: 'Check ownership',
      evidenceIds: [evidenceId],
    } as never,
  }).run()

  store.db.insert(tables.coverageEntries).values({
    id: randomUUID(),
    runId: run.id,
    scopeRevision: 1,
    goalRevision: 1,
    origin,
    category: 'broken-access-control',
    status: 'reported',
    summary: 'Tested BOLA',
    linkedFindingId: findingId,
    assignmentId,
    updatedAt: now,
  }).run()

  store.db.insert(tables.canaries).values({
    id: randomUUID(),
    runId: run.id,
    assignmentId,
    token: `canary-${randomUUID()}`,
    purpose: 'oob-check',
    createdAt: now,
  }).run()

  store.db.insert(tables.sastRuns).values({
    id: randomUUID(),
    runId: run.id,
    assignmentId,
    repo: 'acme/web',
    engine: 'semgrep',
    createdAt: now,
  }).run()

  store.db.insert(tables.surfaceProbes).values({
    id: randomUUID(),
    runId: run.id,
    assignmentId,
    scopeRevision: 1,
    origin,
    probeKind: 'cors',
    createdAt: now,
  }).run()

  store.db.insert(tables.patchProposals).values({
    id: randomUUID(),
    runId: run.id,
    findingId,
    repo: 'acme/web',
    diff: '--- a/x\n+++ b/x',
    codeLocations: [],
    createdAt: now,
    updatedAt: now,
  }).run()

  store.db.insert(tables.reports).values({
    id: randomUUID(),
    runId: run.id,
    version: 1,
    partial: false,
    body: { summary: 'Done', findings: [] } as never,
    createdAt: now,
  }).run()

  store.db.insert(tables.messages).values({
    id: randomUUID(),
    runId: run.id,
    threadId: run.id,
    role: 'coordinator',
    content: 'Finished run',
    createdAt: now,
  }).run()

  const ep1 = randomUUID()
  const ep2 = randomUUID()
  store.db.insert(tables.endpoints).values([
    { id: ep1, runId: run.id, scopeRevision: 1, origin, method: 'POST', pathTemplate: '/api/items', source: 'spa_crawl', createdAt: now, updatedAt: now },
    { id: ep2, runId: run.id, scopeRevision: 1, origin, method: 'GET', pathTemplate: '/api/items/:id', source: 'spa_crawl', createdAt: now, updatedAt: now },
  ]).run()

  store.db.insert(tables.endpointParams).values({
    id: randomUUID(),
    runId: run.id,
    endpointId: ep2,
    name: 'id',
    location: 'path',
    source: 'runtime',
    createdAt: now,
  }).run()

  store.db.insert(tables.apiDependencies).values({
    id: randomUUID(),
    runId: run.id,
    producerEndpointId: ep1,
    consumerEndpointId: ep2,
    resourceKey: 'item_id',
    createdAt: now,
  }).run()

  store.db.insert(tables.secondOrderCanaries).values({
    id: randomUUID(),
    runId: run.id,
    assignmentId,
    marker: `m-${randomUUID()}`,
    injectedOrigin: origin,
    injectedEndpoint: '/api/items',
    injectedParam: 'name',
    createdAt: now,
  }).run()

  store.db.insert(tables.labTelemetry).values({
    id: randomUUID(),
    runId: run.id,
    exchangeId,
    traceId: `tr-${randomUUID()}`,
    artifactId: `tel-${randomUUID()}`,
    createdAt: now,
  }).run()

  const boardSessionId = `board-${randomUUID()}`
  store.db.insert(tables.boardMembers).values({
    id: randomUUID(),
    runId: run.id,
    handle: 'bola',
    role: 'specialist',
    sessionId: boardSessionId,
    state: 'retired',
    scopeRevision: 1,
    goalRevision: 1,
    sourceOrigins: [origin],
    createdAt: now,
    updatedAt: now,
  }).run()

  store.db.insert(tables.boardMessages).values({
    id: randomUUID(),
    runId: run.id,
    seq: 1,
    authorHandle: 'bola',
    authorRole: 'specialist',
    kind: 'verdict',
    mentions: [],
    body: 'Confirmed BOLA',
    refFactIds: [factId],
    refExchangeIds: [exchangeId],
    refFindingIds: [findingId],
    scopeRevision: 1,
    goalRevision: 1,
    sourceOrigins: [origin],
    createdAt: now,
  }).run()

  store.db.insert(tables.resourceSamples).values({
    id: randomUUID(),
    runId: run.id,
    ownerPersona: 'alice',
    resourceKey: 'id',
    collectionPath: '/api/items',
    resourceId: 'item-1',
    origin,
    endpoint: '/api/items',
    method: 'GET',
    createdAt: now,
    updatedAt: now,
  }).run()

  store.db.insert(tables.labContainers).values({
    id: randomUUID(),
    runId: run.id,
    containerName: `lab-${randomUUID()}`,
    status: 'reclaimed',
    createdAt: now,
    updatedAt: now,
  }).run()

  // v8 CapabilityLedger rows (with composite FK from causal_edges -> nodes)
  store.client.prepare(`
    INSERT INTO capability_nodes (
      run_id, cap_id, kind, promotion_status, terminal_impact_oracle_verified,
      provenance, tenant_scope, actor_persona, service_origin, surface,
      temporal_state, parent_hop_receipt_ids_json, artifact_digest, artifact_summary,
      metadata_json, created_at_ms, updated_at_ms
    ) VALUES (?, ?, 'session_token', 'capability_only', 0, 'runtime', 't1', 'alice', ?, 'http', 'active', '[]', 'd1', 'tok', '{}', ?, ?)
  `).run(run.id, 'cap-1', origin, now, now)

  store.client.prepare(`
    INSERT INTO capability_causal_edges (
      run_id, edge_id, precondition_cap_ids_json, actor_context_json,
      hop_receipt_id, edge_binding_kind, postcondition_cap_id,
      source_timestamp_ms, target_timestamp_ms, created_at_ms
    ) VALUES (?, 'edge-1', '[]', '{}', 'hop-1', 'value_binding', 'cap-1', ?, ?, ?)
  `).run(run.id, now, now, now)

  store.client.prepare(`
    INSERT INTO capability_negative_edges (
      run_id, precondition_key, precondition_cap_ids_json, target_surface_key,
      hypothesis_class, falsified_by_exchange_ids_json, reason, created_at_ms, updated_at_ms
    ) VALUES (?, 'k1', '[]', 'GET /api/admin', 'bola', '[]', 'control_blocked_cleanly', ?, ?)
  `).run(run.id, now, now)

  // Immutable append-only audit log row (must NOT block deletion)
  store.appendTenantAuditLog({
    tenantId: 'default',
    runId: run.id,
    actor: 'operator',
    action: 'run.started',
    resourceKind: 'run',
    resourceId: run.id,
    outcome: 'allowed',
  })

  // On-disk artifacts & worker sessions
  const runArtDir = join(dir, 'artifacts', run.id, '00')
  mkdirSync(runArtDir, { recursive: true })
  writeFileSync(join(runArtDir, `${evidenceId}.txt`), 'proof body')
  writeFileSync(join(dir, 'artifacts', `${bodyArtifactId}.txt`), 'legacy flat blob')

  const sessionsDir = join(dir, 'agent-sessions')
  mkdirSync(join(sessionsDir, run.id), { recursive: true })
  writeFileSync(join(sessionsDir, run.id, 'trace.log'), 'trace')
  writeFileSync(join(sessionsDir, `${sessionId}.sqlite`), 'sqlite-bytes')
  writeFileSync(join(sessionsDir, `${sessionId}.sqlite-wal`), 'wal-bytes')
  writeFileSync(join(sessionsDir, `${boardSessionId}.sqlite`), 'board-sqlite')

  const runWorkDir = join(dir, 'runs', run.id)
  mkdirSync(runWorkDir, { recursive: true })
  writeFileSync(join(runWorkDir, 'state.json'), '{}')

  return {
    runId: run.id,
    assignmentId,
    sessionId,
    boardSessionId,
    evidenceId,
    bodyArtifactId,
    findingId,
  }
}

test('deleteRun cascades every SQLite run table, cleans disk files, and preserves sibling runs', withTempStore(({ dir, store }) => {
  const project = store.createProject({
    requestId: randomUUID(),
    name: 'Acme Web',
    seeds: ['https://app.example.com'],
    environment: 'public',
    includeSubdomains: true,
  })
  const target = seedFullRunGraph(store, dir, project.id, 'https://app.example.com')
  const sibling = seedFullRunGraph(store, dir, project.id, 'https://app.example.com')

  // Verify projectDetail reports accurate finding counts before deletion
  const before = store.projectDetail(project.id)
  assert.equal(before.runs.length, 2)
  assert.equal(before.runs.find(r => r.id === target.runId)?.findingCount, 1)
  assert.equal(before.runs.find(r => r.id === target.runId)?.confirmedCount, 1)

  const res = store.deleteRun(target.runId)
  assert.deepEqual(res, { deleted: true, projectId: project.id, runId: target.runId })

  // Idempotent on second delete
  assert.deepEqual(store.deleteRun(target.runId), { deleted: false, projectId: '', runId: target.runId })

  // Every run-scoped table must have 0 rows for target.runId
  const runTables = [
    'runs', 'assignments', 'facts', 'graph_edges', 'graph_digests', 'threat_models',
    'chain_steps', 'broker_exchanges', 'broker_exchanges_fts', 'approval_requests',
    'approval_leases', 'replay_specs', 'retest_runs', 'coverage_entries', 'canaries',
    'evidence', 'findings', 'sast_runs', 'surface_probes', 'patch_proposals', 'reports',
    'messages', 'events', 'endpoints', 'endpoint_params', 'api_dependencies',
    'second_order_canaries', 'lab_telemetry', 'board_members', 'board_messages',
    'resource_samples', 'lab_containers', 'capability_causal_edges',
    'capability_negative_edges', 'capability_nodes',
  ]
  for (const table of runTables) {
    const col = table === 'runs' ? 'id' : 'run_id'
    const row = store.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE ${col} = ?`).get(target.runId) as { c: number }
    assert.equal(Number(row.c), 0, `Expected 0 rows in ${table} for deleted run`)
  }

  // On-disk files for deleted run are removed
  assert.equal(existsSync(join(dir, 'artifacts', target.runId)), false)
  assert.equal(existsSync(join(dir, 'artifacts', `${target.bodyArtifactId}.txt`)), false)
  assert.equal(existsSync(join(dir, 'agent-sessions', `${target.sessionId}.sqlite`)), false)
  assert.equal(existsSync(join(dir, 'agent-sessions', `${target.sessionId}.sqlite-wal`)), false)
  assert.equal(existsSync(join(dir, 'agent-sessions', `${target.boardSessionId}.sqlite`)), false)
  assert.equal(existsSync(join(dir, 'agent-sessions', target.runId)), false)
  assert.equal(existsSync(join(dir, 'runs', target.runId)), false)

  // Sibling run rows and disk files remain intact
  const after = store.projectDetail(project.id)
  assert.equal(after.runs.length, 1)
  assert.equal(after.runs[0]?.id, sibling.runId)
  assert.equal(after.runs[0]?.findingCount, 1)
  assert.equal(existsSync(join(dir, 'artifacts', sibling.runId)), true)
  assert.equal(existsSync(join(dir, 'agent-sessions', `${sibling.sessionId}.sqlite`)), true)
}))

test('deleteProject cascades runs, specs, personas, 0600 credentials, and repo cache without touching other projects', withTempStore(({ dir, store }) => {
  const projectA = store.createProject({
    requestId: randomUUID(),
    name: 'Project Alpha',
    seeds: ['https://alpha.example.com'],
    environment: 'public',
    includeSubdomains: true,
  })
  const projectB = store.createProject({
    requestId: randomUUID(),
    name: 'Project Beta',
    seeds: ['https://beta.example.com'],
    environment: 'public',
    includeSubdomains: true,
  })

  // Seed Project A: 2 runs, spec, persona + minted session file, repo cache dir
  const runA1 = seedFullRunGraph(store, dir, projectA.id, 'https://alpha.example.com')
  const runA2 = seedFullRunGraph(store, dir, projectA.id, 'https://alpha.example.com')
  store.upsertProjectSpecRaw(projectA.id, { name: 'openapi.yaml', kind: 'openapi', content: 'openapi: 3.0.0' })
  createProjectPersona(store, {
    requestId: randomUUID(),
    projectId: projectA.id,
    handle: 'alice',
    roleLabel: 'Member',
    originAllowlist: ['https://alpha.example.com'],
    authKind: 'bearer',
    secret: 'tok-alpha-secret-value',
    canaryMarkers: [],
  })
  const personaARow = store.client.prepare(`SELECT credential_id AS cid FROM personas WHERE project_id = ?`).get(projectA.id) as { cid: string }
  writeFileSync(join(dir, 'credentials', `${personaARow.cid}.session`), '{"headerType":"bearer","value":"v"}', { mode: 0o600 })
  const repoDirA = join(dir, 'repos', projectA.id, 'acme', 'alpha')
  mkdirSync(repoDirA, { recursive: true })
  writeFileSync(join(repoDirA, 'index.ts'), 'export const ok = true\n')

  // Seed Project B: 1 run, persona, repo cache dir
  const runB1 = seedFullRunGraph(store, dir, projectB.id, 'https://beta.example.com')
  createProjectPersona(store, {
    requestId: randomUUID(),
    projectId: projectB.id,
    handle: 'bob',
    roleLabel: 'Member',
    originAllowlist: ['https://beta.example.com'],
    authKind: 'bearer',
    secret: 'tok-beta-secret-value',
    canaryMarkers: [],
  })
  const personaBRow = store.client.prepare(`SELECT credential_id AS cid FROM personas WHERE project_id = ?`).get(projectB.id) as { cid: string }
  const repoDirB = join(dir, 'repos', projectB.id, 'acme', 'beta')
  mkdirSync(repoDirB, { recursive: true })
  writeFileSync(join(repoDirB, 'index.ts'), 'export const beta = true\n')

  const res = store.deleteProject(projectA.id)
  assert.deepEqual(res, { deleted: true, projectId: projectA.id, deletedRuns: 2 })
  assert.deepEqual(store.deleteProject(projectA.id), { deleted: false, projectId: projectA.id, deletedRuns: 0 })

  // Project A database rows are gone
  for (const [table, col] of [
    ['projects', 'id'],
    ['project_assets', 'project_id'],
    ['project_specs', 'project_id'],
    ['personas', 'project_id'],
    ['runs', 'project_id'],
    ['retest_runs', 'project_id'],
  ] as const) {
    const row = store.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE ${col} = ?`).get(projectA.id) as { c: number }
    assert.equal(Number(row.c), 0, `Expected 0 rows in ${table} for deleted project`)
  }

  // Project A files (runs, credentials + .session, repo cache) are removed
  assert.equal(existsSync(join(dir, 'credentials', personaARow.cid)), false)
  assert.equal(existsSync(join(dir, 'credentials', `${personaARow.cid}.session`)), false)
  assert.equal(existsSync(join(dir, 'repos', projectA.id)), false)
  assert.equal(existsSync(join(dir, 'artifacts', runA1.runId)), false)
  assert.equal(existsSync(join(dir, 'artifacts', runA2.runId)), false)

  // Project B remains 100% intact
  const detailB = store.projectDetail(projectB.id)
  assert.equal(detailB.project.name, 'Project Beta')
  assert.equal(detailB.runs.length, 1)
  assert.equal(detailB.runs[0]?.id, runB1.runId)
  assert.equal(detailB.personas.length, 1)
  assert.equal(existsSync(join(dir, 'credentials', personaBRow.cid)), true)
  assert.equal(existsSync(repoDirB), true)
  assert.equal(existsSync(join(dir, 'artifacts', runB1.runId)), true)
}))

test('active-run safety guard refuses deleting active runs/projects unless stopActive: true', withTempStore(async ({ store }) => {
  const project = store.createProject({
    requestId: randomUUID(),
    name: 'Active Target',
    seeds: ['https://active.example.com'],
    environment: 'public',
    includeSubdomains: true,
  })
  const run = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Live assessment',
    capabilityTier: 1,
  }))
  // Simulate an active running state + running worker + lab target
  store.client.prepare(`UPDATE runs SET status = 'running', phase = 'investigation' WHERE id = ?`).run(run.id)
  const workerId = randomUUID()
  store.db.insert(tables.assignments).values({
    id: workerId,
    runId: run.id,
    phase: 'investigation',
    status: 'running',
    scopeRevision: 1,
    goalRevision: 1,
    sessionId: `sess-${randomUUID()}`,
    parentFactIds: [],
    sourceOrigins: ['https://active.example.com'],
    title: 'Active worker',
    objective: 'Probe',
    createdAt: Date.now(),
  }).run()

  let wakeCount = 0
  let labStoppedFor: string[] = []
  let activeLabRuns = new Set<string>([run.id])
  const mockExec = {
    wake: () => {
      wakeCount += 1
      // Emulate Execution.wake() canceling workers on stopped runs
      const current = store.client.prepare(`SELECT status FROM runs WHERE id = ?`).get(run.id) as { status: string } | undefined
      if (current?.status === 'stopped') {
        store.client.prepare(`UPDATE assignments SET status = 'canceled' WHERE run_id = ? AND status = 'running'`).run(run.id)
        activeLabRuns.delete(run.id)
      }
    },
    getLabTargetHandle: (runId: string) => (activeLabRuns.has(runId) ? { runId } : undefined),
  }
  const mockLabRunner = {
    getTarget: (runId: string) => (activeLabRuns.has(runId) ? { runId } : undefined),
    stopLabTarget: async (runId: string) => {
      labStoppedFor.push(runId)
      activeLabRuns.delete(runId)
    },
  }

  // 1. Refuse deleting active run without stopActive
  await assert.rejects(
    () => deleteRunWithActiveGuard(store, mockExec, mockLabRunner, { runId: run.id }),
    /currently active/i,
  )
  assert.equal(store.isRunActive(run.id), true)

  // 2. Refuse deleting project with active run without stopActive
  await assert.rejects(
    () => deleteProjectWithActiveGuard(store, mockExec, mockLabRunner, { projectId: project.id }),
    /active run/i,
  )

  // 3. Stop & delete run succeeds cleanly and stops lab target
  const delRunRes = await deleteRunWithActiveGuard(store, mockExec, mockLabRunner, {
    runId: run.id,
    stopActive: true,
    waitTimeoutMs: 500,
  })
  assert.deepEqual(delRunRes, { deleted: true, projectId: project.id, runId: run.id })
  assert.ok(wakeCount >= 1)
  assert.deepEqual(labStoppedFor, [run.id])

  // 4. Stop & delete project with a new active run succeeds cleanly
  const run2 = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Second active run',
    capabilityTier: 1,
  }))
  store.client.prepare(`UPDATE runs SET status = 'running', phase = 'investigation' WHERE id = ?`).run(run2.id)
  activeLabRuns = new Set([run2.id])
  labStoppedFor = []

  const delProjRes = await deleteProjectWithActiveGuard(store, mockExec, mockLabRunner, {
    projectId: project.id,
    stopActive: true,
    waitTimeoutMs: 500,
  })
  assert.deepEqual(delProjRes, { deleted: true, projectId: project.id, deletedRuns: 1 })
  assert.deepEqual(labStoppedFor, [run2.id])
}))
