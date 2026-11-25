import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { getTableConfig, type SQLiteTable } from 'drizzle-orm/sqlite-core'
import { newRun } from '../src/domain.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import * as schema from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function withTempStore(
  fn: (ctx: { dir: string; store: Store }) => Promise<void> | void,
  options?: ConstructorParameters<typeof Store>[1],
) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), 'guardian-arch-b3-'))
    const store = new Store(dir, options ?? { ftsMode: 'preview' })
    try {
      await fn({ dir, store })
    } finally {
      store.close()
      rmSync(dir, { recursive: true, force: true })
    }
  }
}

const RUN_SCOPED_TABLES = [
  'runs', 'assignments', 'facts', 'graph_edges', 'graph_digests', 'threat_models',
  'chain_steps', 'broker_exchanges', 'broker_exchanges_fts', 'approval_requests',
  'approval_leases', 'replay_specs', 'retest_runs', 'coverage_entries', 'canaries',
  'evidence', 'findings', 'sast_runs', 'surface_probes', 'patch_proposals', 'reports',
  'messages', 'events', 'endpoints', 'endpoint_params', 'api_dependencies',
  'second_order_canaries', 'lab_telemetry', 'board_members', 'board_messages',
  'resource_samples', 'lab_containers', 'capability_causal_edges',
  'capability_negative_edges', 'capability_nodes',
] as const

function seedFullRunGraph(
  store: Store,
  dir: string,
  projectId: string,
  origin: string,
  opts: { sharedBodyArtifactId?: string; skipFts?: boolean } = {},
) {
  const run = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId,
    goal: 'Audit full target surface for cascade test',
    capabilityTier: 2,
  }))
  const now = Date.now()
  const sessionId = `sess-${randomUUID()}`
  const assignmentId = randomUUID()

  store.db.insert(schema.assignments).values({
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
  store.db.insert(schema.facts).values({
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

  store.db.insert(schema.graphEdges).values({
    id: randomUUID(),
    runId: run.id,
    fromKind: 'assignment',
    fromId: assignmentId,
    toKind: 'fact',
    toId: factId,
    edgeKind: 'yields',
    createdAt: now,
  }).run()

  store.db.insert(schema.graphDigests).values({
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

  store.db.insert(schema.threatModels).values({
    id: randomUUID(),
    runId: run.id,
    scopeRevision: 1,
    goalRevision: 1,
    entries: [],
    summary: 'Threat model',
    createdAt: now,
  }).run()

  store.db.insert(schema.chainSteps).values({
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
  const bodyArtifactId = opts.sharedBodyArtifactId ?? `blob-${randomUUID()}`
  store.db.insert(schema.brokerExchanges).values({
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
  if (!opts.skipFts) {
    store.client.prepare(
      `INSERT INTO broker_exchanges_fts (exchange_id, run_id, origin, method, path_and_query, req_headers, resp_headers, body_preview)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(exchangeId, run.id, origin, 'GET', '/api/items', '{}', '{}', '{"ok":true}')
  }

  store.db.insert(schema.approvalRequests).values({
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

  store.db.insert(schema.approvalLeases).values({
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
  store.db.insert(schema.evidence).values({
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
  store.db.insert(schema.replaySpecs).values({
    id: replaySpecId,
    runId: run.id,
    findingId,
    assignmentId,
    scopeRevision: 1,
    goalRevision: 1,
    spec: { version: 1, vulnClass: 'bola', steps: [], assertions: [] } as never,
    specSha256: `sha-${replaySpecId}`,
    sourceOrigins: [origin],
    verifiedInline: true,
    lastVerificationDiff: { verdict: 'confirmed' } as never,
    proofKind: 'agent_script',
    proofVerdict: 'confirmed',
    createdAt: now,
  }).run()

  store.db.insert(schema.retestRuns).values({
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

  store.db.insert(schema.findings).values({
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

  store.db.insert(schema.coverageEntries).values({
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

  store.db.insert(schema.canaries).values({
    id: randomUUID(),
    runId: run.id,
    assignmentId,
    token: `canary-${randomUUID()}`,
    purpose: 'oob-check',
    createdAt: now,
  }).run()

  store.db.insert(schema.sastRuns).values({
    id: randomUUID(),
    runId: run.id,
    assignmentId,
    repo: 'acme/web',
    engine: 'semgrep',
    createdAt: now,
  }).run()

  store.db.insert(schema.surfaceProbes).values({
    id: randomUUID(),
    runId: run.id,
    assignmentId,
    scopeRevision: 1,
    origin,
    probeKind: 'cors',
    createdAt: now,
  }).run()

  store.db.insert(schema.patchProposals).values({
    id: randomUUID(),
    runId: run.id,
    findingId,
    repo: 'acme/web',
    diff: '--- a/x\n+++ b/x',
    codeLocations: [],
    createdAt: now,
    updatedAt: now,
  }).run()

  store.db.insert(schema.reports).values({
    id: randomUUID(),
    runId: run.id,
    version: 1,
    partial: false,
    body: { summary: 'Done', findings: [] } as never,
    createdAt: now,
  }).run()

  store.db.insert(schema.messages).values({
    id: randomUUID(),
    runId: run.id,
    threadId: run.id,
    role: 'coordinator',
    content: 'Finished run',
    createdAt: now,
  }).run()

  store.event(run.id, 'fact.recorded', 'Run-scoped event')

  const ep1 = randomUUID()
  const ep2 = randomUUID()
  store.db.insert(schema.endpoints).values([
    { id: ep1, runId: run.id, scopeRevision: 1, origin, method: 'POST', pathTemplate: '/api/items', source: 'spa_crawl', createdAt: now, updatedAt: now },
    { id: ep2, runId: run.id, scopeRevision: 1, origin, method: 'GET', pathTemplate: '/api/items/:id', source: 'spa_crawl', createdAt: now, updatedAt: now },
  ]).run()

  store.db.insert(schema.endpointParams).values({
    id: randomUUID(),
    runId: run.id,
    endpointId: ep2,
    name: 'id',
    location: 'path',
    source: 'runtime',
    createdAt: now,
  }).run()

  store.db.insert(schema.apiDependencies).values({
    id: randomUUID(),
    runId: run.id,
    producerEndpointId: ep1,
    consumerEndpointId: ep2,
    resourceKey: 'item_id',
    createdAt: now,
  }).run()

  store.db.insert(schema.secondOrderCanaries).values({
    id: randomUUID(),
    runId: run.id,
    assignmentId,
    marker: `m-${randomUUID()}`,
    injectedOrigin: origin,
    injectedEndpoint: '/api/items',
    injectedParam: 'name',
    createdAt: now,
  }).run()

  store.db.insert(schema.labTelemetry).values({
    id: randomUUID(),
    runId: run.id,
    exchangeId,
    traceId: `tr-${randomUUID()}`,
    artifactId: `tel-${randomUUID()}`,
    createdAt: now,
  }).run()

  const boardSessionId = `board-${randomUUID()}`
  store.db.insert(schema.boardMembers).values({
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

  store.db.insert(schema.boardMessages).values({
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

  store.db.insert(schema.resourceSamples).values({
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

  store.db.insert(schema.labContainers).values({
    id: randomUUID(),
    runId: run.id,
    containerName: `lab-${randomUUID()}`,
    status: 'reclaimed',
    createdAt: now,
    updatedAt: now,
  }).run()

  store.client.prepare(`
    INSERT INTO capability_nodes (
      run_id, cap_id, kind, promotion_status, terminal_impact_oracle_verified,
      provenance, tenant_scope, actor_persona, service_origin, surface,
      temporal_state, parent_hop_receipt_ids_json, artifact_digest, artifact_summary,
      metadata_json, created_at_ms, updated_at_ms
    ) VALUES (?, ?, 'scoped_token', 'capability_only', 0, 'runtime_discovery', 't1', 'alice', ?, 'http', 'active', '[]', 'd1', 'tok', '{}', ?, ?)
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

  const auditEntry = store.appendTenantAuditLog({
    tenantId: 'default',
    runId: run.id,
    actor: 'operator',
    action: 'run.started',
    resourceKind: 'run',
    resourceId: run.id,
    outcome: 'allowed',
  })

  // On-disk files
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
    replaySpecId,
    ep1,
    ep2,
    sessionId,
    boardSessionId,
    evidenceId,
    bodyArtifactId,
    findingId,
    auditEntryId: auditEntry.id,
  }
}

function getSchemaTables(): Array<{ exportName: string; config: ReturnType<typeof getTableConfig> }> {
  const results: Array<{ exportName: string; config: ReturnType<typeof getTableConfig> }> = []
  for (const [exportName, value] of Object.entries(schema)) {
    if (!value || typeof value !== 'object') continue
    try {
      const config = getTableConfig(value as SQLiteTable)
      if (config && typeof config.name === 'string' && Array.isArray(config.columns) && config.columns.length > 0) {
        results.push({ exportName, config })
      }
    } catch {
      // Non-table exports (constants, types)
    }
  }
  return results
}

test('schema authority: zero DDL drift across all 41 schema.ts tables, FKs, ON DELETE CASCADE, indexes, and append-only tenant_audit_log', withTempStore(({ store }) => {
  // PRAGMA foreign_keys = ON must be enabled on every Store DB connection
  const fkPragma = store.client.prepare('PRAGMA foreign_keys').get() as { foreign_keys: number }
  assert.equal(Number(fkPragma.foreign_keys), 1, 'PRAGMA foreign_keys must be ON')

  const schemaTables = getSchemaTables()
  assert.equal(schemaTables.length, 41, 'Expected 40 core/feature tables + tenant_audit_log in schema.ts')

  const cascadeParents = new Set(['projects', 'runs', 'assignments', 'replay_specs', 'endpoints'])
  let cascadeFkCount = 0

  for (const { config } of schemaTables) {
    // 1. Table exists with exact column parity (zero missing or extra columns)
    const sqliteCols = (store.client.prepare(`PRAGMA table_info(${config.name})`).all() as Array<{ name: string }>)
      .map(r => r.name)
      .sort()
    const drizzleCols = config.columns.map(c => c.name).sort()
    assert.deepEqual(
      sqliteCols,
      drizzleCols,
      `Column drift detected for table "${config.name}"`,
    )

    // 2. Foreign key parity + ON DELETE CASCADE enforcement
    const sqliteFks = (store.client.prepare(`PRAGMA foreign_key_list(${config.name})`).all() as Array<{
      table: string
      from: string
      to: string
      on_delete: string
    }>).map(fk => ({
      from: fk.from,
      table: fk.table,
      to: fk.to,
      onDelete: fk.on_delete.toUpperCase(),
    })).sort((a, b) => `${a.from}:${a.table}`.localeCompare(`${b.from}:${b.table}`))

    const drizzleFks = config.foreignKeys.map(fk => {
      const ref = fk.reference()
      const refTable = getTableConfig(ref.foreignTable).name
      return {
        from: ref.columns[0]!.name,
        table: refTable,
        to: ref.foreignColumns[0]!.name,
        onDelete: (fk.onDelete ?? 'no action').toUpperCase(),
      }
    }).sort((a, b) => `${a.from}:${a.table}`.localeCompare(`${b.from}:${b.table}`))

    assert.deepEqual(
      sqliteFks,
      drizzleFks,
      `Foreign key / ON DELETE drift detected for table "${config.name}"`,
    )

    for (const fk of sqliteFks) {
      if (cascadeParents.has(fk.table)) {
        assert.equal(
          fk.onDelete,
          'CASCADE',
          `FK ${config.name}.${fk.from} -> ${fk.table}.${fk.to} must use ON DELETE CASCADE`,
        )
        cascadeFkCount += 1
      }
    }

    // 3. Index parity (every declared index in schema.ts exists with matching columns and uniqueness)
    const sqliteIndexes = store.client.prepare(`PRAGMA index_list(${config.name})`).all() as Array<{
      name: string
      unique: number
    }>
    const sqliteIdxMap = new Map<string, { unique: boolean; cols: string[] }>()
    for (const idx of sqliteIndexes) {
      const cols = (store.client.prepare(`PRAGMA index_info(${idx.name})`).all() as Array<{ name: string }>)
        .map(c => c.name)
      sqliteIdxMap.set(idx.name, { unique: idx.unique === 1, cols })
    }
    for (const idx of config.indexes) {
      const actual = sqliteIdxMap.get(idx.config.name)
      assert.ok(actual, `Missing index "${idx.config.name}" on table "${config.name}"`)
      assert.equal(
        actual.unique,
        Boolean(idx.config.unique),
        `Uniqueness mismatch for index "${idx.config.name}" on "${config.name}"`,
      )
      const expectedCols = idx.config.columns.map(col => ('name' in col ? col.name : ''))
      assert.deepEqual(
        actual.cols,
        expectedCols,
        `Column mismatch for index "${idx.config.name}" on "${config.name}"`,
      )
    }
  }

  assert.equal(cascadeFkCount, 46, 'Expected all 46 child foreign keys to enforce ON DELETE CASCADE')

  // CRITICAL SAFETY INVARIANT: tenant_audit_log has NO FK, NO ON DELETE CASCADE, and append-only triggers
  const auditFks = store.client.prepare('PRAGMA foreign_key_list(tenant_audit_log)').all()
  assert.equal(auditFks.length, 0, 'tenant_audit_log must NOT have any foreign keys or ON DELETE CASCADE')
  const triggers = new Set(
    (store.client.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger'").all() as Array<{ name: string }>)
      .map(r => r.name),
  )
  assert.ok(triggers.has('tenant_audit_log_no_update'))
  assert.ok(triggers.has('tenant_audit_log_no_delete'))
  assert.ok(triggers.has('runs_after_delete_capability_ledger'))
  assert.ok(triggers.has('runs_after_delete_fts'))
}))

test('raw SQL DELETE FROM runs cascades every child table while preserving sibling runs, workspace events, and tenant_audit_log', withTempStore(({ dir, store }) => {
  const project = store.createProject({
    requestId: randomUUID(),
    name: 'Cascade Run Target',
    seeds: ['https://run-cascade.example.com'],
    environment: 'public',
    includeSubdomains: true,
  })
  const runA = seedFullRunGraph(store, dir, project.id, 'https://run-cascade.example.com')
  const runB = seedFullRunGraph(store, dir, project.id, 'https://run-cascade.example.com')
  store.event(null, 'workspace.note', 'Workspace-level event must survive run deletion')

  // Raw SQL delete — NO Store helper involved
  store.client.prepare('DELETE FROM runs WHERE id = ?').run(runA.runId)

  // Every run-scoped table must have 0 rows for runA and intact rows for sibling runB
  for (const table of RUN_SCOPED_TABLES) {
    const col = table === 'runs' ? 'id' : 'run_id'
    const countA = Number((store.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE ${col} = ?`).get(runA.runId) as { c: number }).c)
    assert.equal(countA, 0, `Raw DELETE FROM runs must cascade ${table} for deleted run`)

    const countB = Number((store.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE ${col} = ?`).get(runB.runId) as { c: number }).c)
    assert.ok(countB >= 1, `Sibling run rows in ${table} must be preserved`)
  }

  // Workspace-level events (run_id IS NULL) are preserved
  const wsEvents = Number(
    (store.client.prepare("SELECT count(*) AS c FROM events WHERE run_id IS NULL AND kind = 'workspace.note'").get() as { c: number }).c,
  )
  assert.equal(wsEvents, 1)

  // CRITICAL SAFETY INVARIANT: tenant_audit_log rows survive raw run deletion & stay append-only
  const auditA = Number(
    (store.client.prepare('SELECT count(*) AS c FROM tenant_audit_log WHERE run_id = ?').get(runA.runId) as { c: number }).c,
  )
  const auditB = Number(
    (store.client.prepare('SELECT count(*) AS c FROM tenant_audit_log WHERE run_id = ?').get(runB.runId) as { c: number }).c,
  )
  assert.equal(auditA, 1, 'tenant_audit_log entry for deleted run MUST survive')
  assert.equal(auditB, 1, 'tenant_audit_log entry for sibling run MUST survive')
  assert.equal(store.verifyTenantAuditLogChain('default').valid, true)
  assert.throws(
    () => store.client.prepare('DELETE FROM tenant_audit_log WHERE run_id = ?').run(runA.runId),
    /invariant\.audit_log_append_only/,
  )
}))

test('raw SQL DELETE FROM projects cascades runs, specs, personas, assets, and all child rows while preserving sibling projects and tenant_audit_log', withTempStore(({ dir, store }) => {
  const projectA = store.createProject({
    requestId: randomUUID(),
    name: 'Project Alpha',
    seeds: ['https://alpha-cascade.example.com'],
    environment: 'public',
    includeSubdomains: true,
  })
  const projectB = store.createProject({
    requestId: randomUUID(),
    name: 'Project Beta',
    seeds: ['https://beta-cascade.example.com'],
    environment: 'public',
    includeSubdomains: true,
  })

  const runA1 = seedFullRunGraph(store, dir, projectA.id, 'https://alpha-cascade.example.com')
  const runA2 = seedFullRunGraph(store, dir, projectA.id, 'https://alpha-cascade.example.com')
  store.upsertProjectSpecRaw(projectA.id, { name: 'alpha.yaml', kind: 'openapi', content: 'openapi: 3.0.0' })
  createProjectPersona(store, {
    requestId: randomUUID(),
    projectId: projectA.id,
    handle: 'alice',
    roleLabel: 'Member',
    originAllowlist: ['https://alpha-cascade.example.com'],
    authKind: 'bearer',
    secret: 'tok-alpha-cascade',
    canaryMarkers: [],
  })

  const runB1 = seedFullRunGraph(store, dir, projectB.id, 'https://beta-cascade.example.com')
  store.upsertProjectSpecRaw(projectB.id, { name: 'beta.yaml', kind: 'openapi', content: 'openapi: 3.0.0' })
  createProjectPersona(store, {
    requestId: randomUUID(),
    projectId: projectB.id,
    handle: 'bob',
    roleLabel: 'Member',
    originAllowlist: ['https://beta-cascade.example.com'],
    authKind: 'bearer',
    secret: 'tok-beta-cascade',
    canaryMarkers: [],
  })

  // Raw SQL delete on projects — NO Store helper involved
  store.client.prepare('DELETE FROM projects WHERE id = ?').run(projectA.id)

  for (const [table, col] of [
    ['projects', 'id'],
    ['project_assets', 'project_id'],
    ['project_specs', 'project_id'],
    ['personas', 'project_id'],
    ['runs', 'project_id'],
    ['retest_runs', 'project_id'],
  ] as const) {
    const countA = Number((store.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE ${col} = ?`).get(projectA.id) as { c: number }).c)
    assert.equal(countA, 0, `Raw DELETE FROM projects must cascade ${table} for projectA`)
    const countB = Number((store.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE ${col} = ?`).get(projectB.id) as { c: number }).c)
    assert.ok(countB >= 1, `Sibling projectB rows in ${table} must be preserved`)
  }

  for (const runId of [runA1.runId, runA2.runId]) {
    for (const table of RUN_SCOPED_TABLES) {
      const col = table === 'runs' ? 'id' : 'run_id'
      const count = Number((store.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE ${col} = ?`).get(runId) as { c: number }).c)
      assert.equal(count, 0, `Raw DELETE FROM projects must transitively cascade ${table} for run ${runId}`)
    }
  }
  for (const table of RUN_SCOPED_TABLES) {
    const col = table === 'runs' ? 'id' : 'run_id'
    const countB = Number((store.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE ${col} = ?`).get(runB1.runId) as { c: number }).c)
    assert.ok(countB >= 1, `Sibling projectB run rows in ${table} must survive`)
  }

  // CRITICAL SAFETY INVARIANT: tenant_audit_log rows for deleted project's runs survive
  for (const runId of [runA1.runId, runA2.runId, runB1.runId]) {
    const auditCount = Number(
      (store.client.prepare('SELECT count(*) AS c FROM tenant_audit_log WHERE run_id = ?').get(runId) as { c: number }).c,
    )
    assert.equal(auditCount, 1, `tenant_audit_log entry for run ${runId} MUST survive project deletion`)
  }
  assert.equal(store.verifyTenantAuditLogChain('default').valid, true)
}))

test('raw SQL intermediate cascades on assignments, endpoints, and replay_specs', withTempStore(({ dir, store }) => {
  const project = store.createProject({
    requestId: randomUUID(),
    name: 'Intermediate Cascade',
    seeds: ['https://mid.example.com'],
    environment: 'public',
    includeSubdomains: true,
  })
  const seeded = seedFullRunGraph(store, dir, project.id, 'https://mid.example.com')

  // 1. Deleting replay_specs cascades retest_runs
  store.client.prepare('DELETE FROM replay_specs WHERE id = ?').run(seeded.replaySpecId)
  assert.equal(
    Number((store.client.prepare('SELECT count(*) AS c FROM retest_runs WHERE run_id = ?').get(seeded.runId) as { c: number }).c),
    0,
  )

  // 2. Deleting an endpoint cascades endpoint_params and api_dependencies (both consumer and producer)
  store.client.prepare('DELETE FROM endpoints WHERE id = ?').run(seeded.ep2)
  assert.equal(
    Number((store.client.prepare('SELECT count(*) AS c FROM endpoint_params WHERE endpoint_id = ?').get(seeded.ep2) as { c: number }).c),
    0,
  )
  assert.equal(
    Number((store.client.prepare('SELECT count(*) AS c FROM api_dependencies WHERE consumer_endpoint_id = ?').get(seeded.ep2) as { c: number }).c),
    0,
  )

  // 3. Deleting an assignment cascades facts, broker_exchanges, approval_requests, evidence, sast_runs, surface_probes
  store.client.prepare('DELETE FROM assignments WHERE id = ?').run(seeded.assignmentId)
  for (const table of ['facts', 'broker_exchanges', 'approval_requests', 'evidence', 'sast_runs', 'surface_probes'] as const) {
    const count = Number(
      (store.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE assignment_id = ?`).get(seeded.assignmentId) as { c: number }).c,
    )
    assert.equal(count, 0, `Deleting assignment must cascade ${table}`)
  }
}))

test('raw SQL DELETE FROM runs works cleanly when ftsMode is off (no FTS table)', withTempStore(({ dir, store }) => {
  const project = store.createProject({
    requestId: randomUUID(),
    name: 'No-FTS Target',
    seeds: ['https://nofts.example.com'],
    environment: 'public',
    includeSubdomains: true,
  })
  const seeded = seedFullRunGraph(store, dir, project.id, 'https://nofts.example.com', { skipFts: true })

  store.client.prepare('DELETE FROM runs WHERE id = ?').run(seeded.runId)
  assert.equal(
    Number((store.client.prepare('SELECT count(*) AS c FROM runs WHERE id = ?').get(seeded.runId) as { c: number }).c),
    0,
  )
  assert.equal(
    Number((store.client.prepare('SELECT count(*) AS c FROM broker_exchanges WHERE run_id = ?').get(seeded.runId) as { c: number }).c),
    0,
  )
  assert.equal(
    Number((store.client.prepare('SELECT count(*) AS c FROM tenant_audit_log WHERE run_id = ?').get(seeded.runId) as { c: number }).c),
    1,
  )
}, { ftsMode: 'off' }))

test('Store.deleteRun and Store.deleteProject work cleanly on fresh cascaded DBs (preserving shared blobs, siblings, and tenant_audit_log)', withTempStore(({ dir, store }) => {
  const projectA = store.createProject({
    requestId: randomUUID(),
    name: 'Fresh Project A',
    seeds: ['https://fresh-a.example.com'],
    environment: 'public',
    includeSubdomains: true,
  })
  const projectB = store.createProject({
    requestId: randomUUID(),
    name: 'Fresh Project B',
    seeds: ['https://fresh-b.example.com'],
    environment: 'public',
    includeSubdomains: true,
  })

  const sharedBlob = `shared-blob-${randomUUID()}`
  const runA1 = seedFullRunGraph(store, dir, projectA.id, 'https://fresh-a.example.com', { sharedBodyArtifactId: sharedBlob })
  const runA2 = seedFullRunGraph(store, dir, projectA.id, 'https://fresh-a.example.com')
  const runB1 = seedFullRunGraph(store, dir, projectB.id, 'https://fresh-b.example.com', { sharedBodyArtifactId: sharedBlob })

  createProjectPersona(store, {
    requestId: randomUUID(),
    projectId: projectA.id,
    handle: 'alice',
    roleLabel: 'Member',
    originAllowlist: ['https://fresh-a.example.com'],
    authKind: 'bearer',
    secret: 'tok-fresh-a',
    canaryMarkers: [],
  })
  const credA = (store.client.prepare('SELECT credential_id AS cid FROM personas WHERE project_id = ?').get(projectA.id) as { cid: string }).cid
  writeFileSync(join(dir, 'credentials', `${credA}.session`), '{"headerType":"bearer","value":"v"}', { mode: 0o600 })
  const repoDirA = join(dir, 'repos', projectA.id, 'org', 'app')
  mkdirSync(repoDirA, { recursive: true })
  writeFileSync(join(repoDirA, 'index.ts'), 'export {}\n')

  // 1. Delete single runA1 via Store.deleteRun: shared flat blob referenced by runB1 must remain on disk
  assert.deepEqual(store.deleteRun(runA1.runId), { deleted: true, projectId: projectA.id, runId: runA1.runId })
  assert.equal(existsSync(join(dir, 'artifacts', runA1.runId)), false)
  assert.equal(existsSync(join(dir, 'agent-sessions', `${runA1.sessionId}.sqlite`)), false)
  assert.equal(existsSync(join(dir, 'runs', runA1.runId)), false)
  assert.equal(existsSync(join(dir, 'artifacts', `${sharedBlob}.txt`)), true, 'Shared flat blob referenced by runB1 must remain on disk')
  assert.equal(
    Number((store.client.prepare('SELECT count(*) AS c FROM tenant_audit_log WHERE run_id = ?').get(runA1.runId) as { c: number }).c),
    1,
  )

  // 2. Delete projectA via Store.deleteProject: cleans runA2, credentials, repo cache, preserves projectB & audit log
  assert.deepEqual(store.deleteProject(projectA.id), { deleted: true, projectId: projectA.id, deletedRuns: 1 })
  assert.equal(existsSync(join(dir, 'artifacts', runA2.runId)), false)
  assert.equal(existsSync(join(dir, 'artifacts', `${runA2.bodyArtifactId}.txt`)), false)
  assert.equal(existsSync(join(dir, 'credentials', credA)), false)
  assert.equal(existsSync(join(dir, 'credentials', `${credA}.session`)), false)
  assert.equal(existsSync(join(dir, 'repos', projectA.id)), false)

  // Project B remains 100% intact
  assert.equal(store.projectDetail(projectB.id).runs.length, 1)
  assert.equal(existsSync(join(dir, 'artifacts', runB1.runId)), true)
  assert.equal(existsSync(join(dir, 'artifacts', `${sharedBlob}.txt`)), true)
  assert.equal(
    Number((store.client.prepare('SELECT count(*) AS c FROM tenant_audit_log WHERE run_id = ?').get(runA2.runId) as { c: number }).c),
    1,
  )
}))

test('Store.deleteRun and Store.deleteProject stay 100% backward-compatible on legacy pre-cascade SQLite DBs', () => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-arch-b3-legacy-'))
  try {
    // Bootstrap a genuine pre-cascade SQLite DB from the legacy v2 Drizzle migration SQL (0 ON DELETE CASCADE!)
    const legacySql = readFileSync(
      join(REPO_ROOT, 'drizzle', '20261120220711_guardian_v2_initial', 'migration.sql'),
      'utf8',
    )
    const raw = new DatabaseSync(join(dir, 'guardian.sqlite'))
    for (const stmt of legacySql.split('--> statement-breakpoint')) {
      const trimmed = stmt.trim()
      if (trimmed) raw.exec(trimmed)
    }
    raw.close()

    // Open with Store — must upgrade additively without rebuilding legacy tables, and keep PRAGMA foreign_keys = ON
    const store = new Store(dir, { ftsMode: 'preview' })
    try {
      const fkPragma = store.client.prepare('PRAGMA foreign_keys').get() as { foreign_keys: number }
      assert.equal(Number(fkPragma.foreign_keys), 1)

      // Confirm this DB genuinely lacks ON DELETE CASCADE on legacy core tables
      const legacyFks = store.client.prepare('PRAGMA foreign_key_list(assignments)').all() as Array<{
        table: string
        on_delete: string
      }>
      assert.equal(legacyFks.find(fk => fk.table === 'runs')?.on_delete.toUpperCase(), 'NO ACTION')

      const projectA = store.createProject({
        requestId: randomUUID(),
        name: 'Legacy Alpha',
        seeds: ['https://legacy-a.example.com'],
        environment: 'public',
        includeSubdomains: true,
      })
      const projectB = store.createProject({
        requestId: randomUUID(),
        name: 'Legacy Beta',
        seeds: ['https://legacy-b.example.com'],
        environment: 'public',
        includeSubdomains: true,
      })

      const runA1 = seedFullRunGraph(store, dir, projectA.id, 'https://legacy-a.example.com')
      const runA2 = seedFullRunGraph(store, dir, projectA.id, 'https://legacy-a.example.com')
      const runB1 = seedFullRunGraph(store, dir, projectB.id, 'https://legacy-b.example.com')

      store.upsertProjectSpecRaw(projectA.id, { name: 'legacy.yaml', kind: 'openapi', content: 'openapi: 3.0.0' })
      createProjectPersona(store, {
        requestId: randomUUID(),
        projectId: projectA.id,
        handle: 'alice',
        roleLabel: 'Member',
        originAllowlist: ['https://legacy-a.example.com'],
        authKind: 'bearer',
        secret: 'tok-legacy-a',
        canaryMarkers: [],
      })
      const credA = (store.client.prepare('SELECT credential_id AS cid FROM personas WHERE project_id = ?').get(projectA.id) as { cid: string }).cid
      writeFileSync(join(dir, 'credentials', `${credA}.session`), '{"headerType":"bearer","value":"v"}', { mode: 0o600 })
      const repoDirA = join(dir, 'repos', projectA.id, 'acme', 'legacy')
      mkdirSync(repoDirA, { recursive: true })
      writeFileSync(join(repoDirA, 'index.ts'), 'export const legacy = true\n')

      // Raw DELETE FROM runs fails on legacy DB (confirming fallback is truly exercised!)
      assert.throws(
        () => store.client.prepare('DELETE FROM runs WHERE id = ?').run(runA1.runId),
        /FOREIGN KEY constraint failed/,
      )

      // 1. Store.deleteRun succeeds cleanly via legacy topological fallback
      assert.deepEqual(store.deleteRun(runA1.runId), { deleted: true, projectId: projectA.id, runId: runA1.runId })
      for (const table of RUN_SCOPED_TABLES) {
        const col = table === 'runs' ? 'id' : 'run_id'
        const count = Number((store.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE ${col} = ?`).get(runA1.runId) as { c: number }).c)
        assert.equal(count, 0, `Legacy deleteRun must clear ${table}`)
      }
      assert.equal(existsSync(join(dir, 'artifacts', runA1.runId)), false)
      assert.equal(existsSync(join(dir, 'agent-sessions', `${runA1.sessionId}.sqlite`)), false)
      assert.equal(existsSync(join(dir, 'runs', runA1.runId)), false)
      assert.equal(
        Number((store.client.prepare('SELECT count(*) AS c FROM tenant_audit_log WHERE run_id = ?').get(runA1.runId) as { c: number }).c),
        1,
      )

      // 2. Store.deleteProject succeeds cleanly via legacy topological fallback
      assert.deepEqual(store.deleteProject(projectA.id), { deleted: true, projectId: projectA.id, deletedRuns: 1 })
      for (const [table, col] of [
        ['projects', 'id'],
        ['project_assets', 'project_id'],
        ['project_specs', 'project_id'],
        ['personas', 'project_id'],
        ['runs', 'project_id'],
        ['retest_runs', 'project_id'],
      ] as const) {
        const count = Number((store.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE ${col} = ?`).get(projectA.id) as { c: number }).c)
        assert.equal(count, 0, `Legacy deleteProject must clear ${table}`)
      }
      for (const table of RUN_SCOPED_TABLES) {
        const col = table === 'runs' ? 'id' : 'run_id'
        const count = Number((store.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE ${col} = ?`).get(runA2.runId) as { c: number }).c)
        assert.equal(count, 0, `Legacy deleteProject must clear ${table} for runA2`)
      }
      assert.equal(existsSync(join(dir, 'credentials', credA)), false)
      assert.equal(existsSync(join(dir, 'credentials', `${credA}.session`)), false)
      assert.equal(existsSync(join(dir, 'repos', projectA.id)), false)
      assert.equal(existsSync(join(dir, 'artifacts', runA2.runId)), false)

      // Project B and all tenant_audit_log rows remain 100% intact
      assert.equal(store.projectDetail(projectB.id).runs.length, 1)
      assert.equal(existsSync(join(dir, 'artifacts', runB1.runId)), true)
      for (const runId of [runA1.runId, runA2.runId, runB1.runId]) {
        const auditCount = Number(
          (store.client.prepare('SELECT count(*) AS c FROM tenant_audit_log WHERE run_id = ?').get(runId) as { c: number }).c,
        )
        assert.equal(auditCount, 1, `tenant_audit_log entry for ${runId} MUST survive legacy deletion`)
      }
      assert.equal(store.verifyTenantAuditLogChain('default').valid, true)
    } finally {
      store.close()
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
