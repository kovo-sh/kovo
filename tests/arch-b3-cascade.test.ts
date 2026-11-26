import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { getTableConfig, type SQLiteTable } from 'drizzle-orm/sqlite-core'
import { newRun } from '../src/domain.ts'
import { purgeExpiredArtifacts } from '../src/server/artifact-ttl.ts'
import { CITING_COLUMNS, validateCitingColumnsAgainstTables } from '../src/server/evidence-citations.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import * as schema from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function withTempStore(
  fn: (ctx: { dir: string; store: Store }) => Promise<void> | void,
  options?: ConstructorParameters<typeof Store>[1],
) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-arch-b3-'))
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

function normalizeDrizzleDefault(col: ReturnType<typeof getTableConfig>['columns'][number]): string | null {
  if (!col.hasDefault || col.default === undefined) return null
  if (typeof col.default === 'boolean') return col.default ? '1' : '0'
  if (typeof col.default === 'object') return JSON.stringify(col.default)
  return String(col.default)
}

function normalizeSqliteDefault(raw: string | null): string | null {
  if (raw === null) return null
  const trimmed = raw.trim()
  if (trimmed.length >= 2 && trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replace(/''/g, "'")
  }
  return trimmed
}

test('schema authority: zero DDL drift across all schema.ts tables, columns, defaults, NOT NULL, FKs, ON DELETE CASCADE, indexes, and append-only tenant_audit_log', withTempStore(({ store }) => {
  // PRAGMA foreign_keys = ON must be enabled on every Store DB connection
  const fkPragma = store.client.prepare('PRAGMA foreign_keys').get() as { foreign_keys: number }
  assert.equal(Number(fkPragma.foreign_keys), 1, 'PRAGMA foreign_keys must be ON')

  const schemaTables = getSchemaTables()
  assert.ok(schemaTables.length > 0, 'Expected Drizzle schema tables to be exported by schema.ts')

  // Derive expected table set from Drizzle config and confirm exact parity with non-virtual, non-ledger SQLite tables.
  const drizzleTableNames = schemaTables.map(t => t.config.name).sort()
  const sqliteManagedTables = (store.client.prepare(
    `SELECT name FROM sqlite_master
     WHERE type = 'table'
       AND name NOT LIKE 'sqlite_%'
       AND name NOT LIKE 'broker_exchanges_fts%'
       AND name NOT LIKE 'capability_%'
     ORDER BY name`,
  ).all() as Array<{ name: string }>).map(r => r.name)
  assert.deepEqual(
    sqliteManagedTables,
    drizzleTableNames,
    'Managed SQLite tables must match Drizzle schema.ts exports with zero extra or missing tables',
  )

  const cascadeParents = new Set(['projects', 'runs', 'assignments', 'replay_specs', 'endpoints'])
  let expectedCascadeFkCount = 0
  let cascadeFkCount = 0

  for (const { config } of schemaTables) {
    // 1. Table exists with exact column name, NOT NULL, and default parity
    const sqliteInfo = store.client.prepare(`PRAGMA table_info(${config.name})`).all() as Array<{
      name: string
      notnull: number
      dflt_value: string | null
      pk: number
    }>
    const sqliteCols = sqliteInfo.map(r => r.name).sort()
    const drizzleCols = config.columns.map(c => c.name).sort()
    assert.deepEqual(
      sqliteCols,
      drizzleCols,
      `Column drift detected for table "${config.name}"`,
    )
    const sqliteByName = new Map(sqliteInfo.map(r => [r.name, r]))
    for (const col of config.columns) {
      const sq = sqliteByName.get(col.name)
      assert.ok(sq, `Missing SQLite column "${config.name}.${col.name}"`)
      const expectedNotNull = Boolean(col.notNull || col.primary)
      const actualNotNull = Boolean(sq.notnull || sq.pk)
      assert.equal(
        actualNotNull,
        expectedNotNull,
        `NOT NULL drift on "${config.name}.${col.name}" (expected ${expectedNotNull}, got ${actualNotNull})`,
      )
      const expectedDefault = normalizeDrizzleDefault(col)
      const actualDefault = normalizeSqliteDefault(sq.dflt_value)
      assert.equal(
        actualDefault,
        expectedDefault,
        `DEFAULT drift on "${config.name}.${col.name}" (expected ${JSON.stringify(expectedDefault)}, got ${JSON.stringify(actualDefault)})`,
      )
    }

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

    for (const fk of drizzleFks) {
      if (cascadeParents.has(fk.table)) expectedCascadeFkCount += 1
    }
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

  assert.equal(cascadeFkCount, expectedCascadeFkCount, 'Every child FK pointing to a cascade parent must enforce ON DELETE CASCADE')
  assert.ok(cascadeFkCount > 0)

  // Shared evidence-citations registry must match schema.ts with zero drift.
  assert.deepEqual(
    validateCitingColumnsAgainstTables(schemaTables.map(t => t.config)),
    [],
    'evidence-citations.ts CITING_COLUMNS must match every citing column in schema.ts',
  )

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
  assert.ok(triggers.has('findings_confirmation_evidence_insert'))
  assert.ok(triggers.has('findings_confirmation_evidence_update'))
  assert.ok(triggers.has('findings_sync_promoted_insert'))
  assert.ok(triggers.has('findings_sync_promoted_update'))
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
  const dir = mkdtempSync(join(tmpdir(), 'kovo-arch-b3-legacy-'))
  try {
    // Bootstrap a genuine pre-cascade SQLite DB from the legacy v2 Drizzle migration SQL (0 ON DELETE CASCADE!)
    const legacySql = readFileSync(
      join(REPO_ROOT, 'drizzle', '20261120220711_guardian_v2_initial', 'migration.sql'),
      'utf8',
    )
    const raw = new DatabaseSync(join(dir, 'kovo.sqlite'))
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

test('R2-12 Store.verifySchema fails closed on injected drift and self-repairs known v10 user-dir drift', () => {
  // 1. Injected unexpected column causes Store open to fail closed
  const dirUnexpected = mkdtempSync(join(tmpdir(), 'kovo-r212-drift-extra-'))
  try {
    const initial = new Store(dirUnexpected, { ftsMode: 'off' })
    initial.close()
    const raw = new DatabaseSync(join(dirUnexpected, 'kovo.sqlite'))
    raw.exec('ALTER TABLE runs ADD COLUMN rogue_drift_col TEXT;')
    raw.close()
    assert.throws(
      () => new Store(dirUnexpected, { ftsMode: 'off' }),
      /Schema verification failed.*unexpected column "runs\.rogue_drift_col"/,
    )
  } finally {
    rmSync(dirUnexpected, { recursive: true, force: true })
  }

  // 2. Dropped non-repairable column causes Store open to fail closed
  const dirMissing = mkdtempSync(join(tmpdir(), 'kovo-r212-drift-missing-'))
  try {
    const initial = new Store(dirMissing, { ftsMode: 'off' })
    initial.close()
    const raw = new DatabaseSync(join(dirMissing, 'kovo.sqlite'))
    raw.exec('ALTER TABLE findings DROP COLUMN counterevidence;')
    raw.close()
    assert.throws(
      () => new Store(dirMissing, { ftsMode: 'off' }),
      /Schema verification failed.*missing column "findings\.counterevidence"/,
    )
  } finally {
    rmSync(dirMissing, { recursive: true, force: true })
  }

  // 3. Existing user DB with historical v10 drift (missing operations.created_at) + lazy runs columns self-repairs cleanly
  const dirRepair = mkdtempSync(join(tmpdir(), 'kovo-r212-drift-repair-'))
  try {
    const initial = new Store(dirRepair, { ftsMode: 'off' })
    initial.close()
    const raw = new DatabaseSync(join(dirRepair, 'kovo.sqlite'))
    raw.exec('DROP INDEX IF EXISTS operations_created;')
    raw.exec('ALTER TABLE operations DROP COLUMN created_at;')
    raw.exec("ALTER TABLE runs ADD COLUMN declined_origins TEXT NOT NULL DEFAULT '[]';")
    raw.exec('ALTER TABLE runs ADD COLUMN label TEXT;')
    raw.close()
    const repaired = new Store(dirRepair, { ftsMode: 'off' })
    try {
      repaired.verifySchema()
      const opsCols = (repaired.client.prepare('PRAGMA table_info(operations)').all() as Array<{ name: string }>).map(c => c.name)
      assert.ok(opsCols.includes('created_at'), 'repair migration must restore operations.created_at')
    } finally {
      repaired.close()
    }
  } finally {
    rmSync(dirRepair, { recursive: true, force: true })
  }

  // 4. Schema-walk check catches an unregistered synthetic citing column
  const syntheticDrift = validateCitingColumnsAgainstTables([
    ...getSchemaTables().map(t => t.config),
    { name: 'synthetic_table', columns: [{ name: 'id' }, { name: 'new_artifact_id' }] },
  ])
  assert.ok(
    syntheticDrift.some(v => v.includes('synthetic_table.new_artifact_id')),
    `Expected unregistered citing column to be flagged, got: ${syntheticDrift.join('; ')}`,
  )
  assert.ok(CITING_COLUMNS.some(c => c.table === 'sast_runs' && c.column === 'raw_artifact_id'))
  assert.ok(CITING_COLUMNS.some(c => c.table === 'messages' && c.column === 'evidence_ids'))
  assert.ok(CITING_COLUMNS.some(c => c.table === 'lab_telemetry' && c.column === 'artifact_id'))
})

test('R2-12 fail-closed decoders: corrupt declined_origins throws & blocks admission, and artifact-ttl aborts on protection error while protecting sast_runs/messages/lab_telemetry', withTempStore(({ dir, store }) => {
  const project = store.createProject({
    requestId: randomUUID(),
    name: 'Fail-Closed Safety Target',
    seeds: ['https://safety.example.com'],
    environment: 'public',
    includeSubdomains: true,
  })
  const createdRun = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify fail-closed decoders and evidence protection',
    capabilityTier: 2,
  }))
  const run = store.run(createdRun.id)
  const origin = 'https://safety.example.com'

  // 1. Store.hasExplicitEnvironmentMode public hook (R2-01 completion)
  assert.equal(store.hasExplicitEnvironmentMode(run.id), false)
  store.setEnvironmentMode(store.run(run.id), 'staging_isolated')
  assert.equal(store.hasExplicitEnvironmentMode(run.id), true)

  // 2. getDeclinedOrigins / isOriginDeclined / admitDynamicOrigin fail closed on corrupt JSON
  store.runsRepo.setOriginRole(store.run(run.id), 'https://declined.safety.example.com', 'asset')
  assert.equal(store.runsRepo.isOriginDeclined(run.id, 'https://declined.safety.example.com'), true)

  store.client.prepare('UPDATE runs SET declined_origins = ? WHERE id = ?').run('{corrupt-json', run.id)
  assert.throws(
    () => store.runsRepo.getDeclinedOrigins(run.id),
    /Corrupt runs\.declined_origins JSON/,
  )
  assert.throws(
    () => store.runsRepo.isOriginDeclined(run.id, 'https://declined.safety.example.com'),
    /Corrupt runs\.declined_origins JSON/,
  )
  assert.throws(
    () => store.runsRepo.admitDynamicOrigin({
      runId: run.id,
      origin: 'https://declined.safety.example.com',
      source: 'test',
    }),
    /Corrupt runs\.declined_origins JSON/,
  )
  // Restore valid declined_origins JSON before continuing
  store.client.prepare('UPDATE runs SET declined_origins = ? WHERE id = ?').run('[]', run.id)

  // 3. artifact-ttl protects sast_runs.raw_artifact_id, messages.evidence_ids, lab_telemetry.artifact_id
  const oldTs = Date.now() - 10 * 24 * 60 * 60_000
  const assignmentId = randomUUID()
  store.db.insert(schema.assignments).values({
    id: assignmentId,
    runId: run.id,
    phase: 'investigation',
    status: 'complete',
    scopeRevision: 1,
    goalRevision: 1,
    sessionId: `sess-${randomUUID()}`,
    parentFactIds: [],
    sourceOrigins: [origin],
    title: 'TTL check',
    objective: 'Seed evidence',
    createdAt: oldTs,
  }).run()

  const sastEvId = `ev-sast-${randomUUID()}`
  const msgEvId = `ev-msg-${randomUUID()}`
  const telEvId = `ev-tel-${randomUUID()}`
  const orphanEvId = `ev-orphan-${randomUUID()}`
  for (const id of [sastEvId, msgEvId, telEvId, orphanEvId]) {
    store.db.insert(schema.evidence).values({
      id,
      runId: run.id,
      assignmentId,
      scopeRevision: 1,
      goalRevision: 1,
      title: `Evidence ${id}`,
      kind: 'exchange',
      createdAt: oldTs,
    }).run()
  }
  store.db.insert(schema.sastRuns).values({
    id: randomUUID(),
    runId: run.id,
    assignmentId,
    repo: 'acme/app',
    engine: 'semgrep',
    rawArtifactId: sastEvId,
    createdAt: oldTs,
  }).run()
  const msgId = randomUUID()
  store.db.insert(schema.messages).values({
    id: msgId,
    runId: run.id,
    threadId: run.id,
    role: 'coordinator',
    content: 'Cited evidence',
    evidenceIds: [msgEvId],
    createdAt: oldTs,
  }).run()
  store.db.insert(schema.labTelemetry).values({
    id: randomUUID(),
    runId: run.id,
    exchangeId: randomUUID(),
    traceId: `tr-${randomUUID()}`,
    artifactId: telEvId,
    createdAt: oldTs,
  }).run()
  store.client.prepare("UPDATE runs SET status = 'complete' WHERE id = ?").run(run.id)

  // 4. Corrupt JSON in a citing column MUST abort the entire TTL prune with ZERO deletions!
  store.client.prepare('UPDATE messages SET evidence_ids = ? WHERE id = ?').run('{not-valid-json', msgId)
  assert.throws(
    () => purgeExpiredArtifacts(store, { runId: run.id, artifactTtlMs: 1_000, now: Date.now() }),
    /Evidence protection aborted: corrupt JSON in messages\.evidence_ids/,
  )
  const remainingAfterAbort = (store.client.prepare('SELECT id FROM evidence WHERE run_id = ?').all(run.id) as Array<{ id: string }>)
    .map(r => r.id)
    .sort()
  assert.deepEqual(
    remainingAfterAbort,
    [msgEvId, orphanEvId, sastEvId, telEvId].sort(),
    'Aborted TTL prune must delete ZERO evidence rows',
  )

  // Fix messages.evidence_ids -> prune deletes ONLY the unreferenced orphan while protecting all 3 cited rows
  store.client.prepare('UPDATE messages SET evidence_ids = ? WHERE id = ?').run(JSON.stringify([msgEvId]), msgId)
  const purged = purgeExpiredArtifacts(store, { runId: run.id, artifactTtlMs: 1_000, now: Date.now() })
  assert.equal(purged.artifactsDeleted, 1)
  const remainingAfterPurge = (store.client.prepare('SELECT id FROM evidence WHERE run_id = ?').all(run.id) as Array<{ id: string }>)
    .map(r => r.id)
    .sort()
  assert.deepEqual(
    remainingAfterPurge,
    [msgEvId, sastEvId, telEvId].sort(),
    'TTL prune must preserve evidence cited by sast_runs.raw_artifact_id, messages.evidence_ids, and lab_telemetry.artifact_id',
  )

  // 5. Store.upsertFindingRecord enforces explicit run_id predicate (cross-run UPDATE cannot clobber sibling run)
  const createdSiblingRun = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Sibling run isolation check',
    capabilityTier: 1,
  }))
  const siblingRun = store.run(createdSiblingRun.id)
  const baselineId = randomUUID()
  store.upsertFindingRecord({
    runId: run.id,
    assetId: origin,
    goalRevision: run.goalRevision,
    findingId: baselineId,
    checkId: 'hsts',
    caseId: 'hsts-1',
    findingKind: 'baseline_check',
    sourceOrigins: [origin],
    verificationTier: 'baseline_confirmed',
    verificationClass: 'runtime_confirmed',
    finding: {
      id: baselineId,
      origin,
      title: 'Original baseline title',
      status: 'confirmed',
      severity: 'low',
      reason: 'Missing HSTS',
      remediation: 'Enable HSTS',
      evidenceIds: [],
      scopeRevision: run.scopeRevision,
      findingKind: 'baseline_check',
      verificationTier: 'baseline_confirmed',
    },
  })
  store.upsertFindingRecord({
    runId: siblingRun.id,
    assetId: origin,
    goalRevision: siblingRun.goalRevision,
    findingId: baselineId,
    existingId: baselineId,
    checkId: 'hsts',
    caseId: 'hsts-1',
    findingKind: 'baseline_check',
    sourceOrigins: [origin],
    verificationTier: 'baseline_confirmed',
    verificationClass: 'runtime_confirmed',
    finding: {
      id: baselineId,
      origin,
      title: 'Cross-run clobber attempt',
      status: 'confirmed',
      severity: 'critical',
      reason: 'Should not modify run 1',
      remediation: 'None',
      evidenceIds: [],
      scopeRevision: siblingRun.scopeRevision,
      findingKind: 'baseline_check',
      verificationTier: 'baseline_confirmed',
    },
  })
  const preserved = store.client.prepare('SELECT finding, severity FROM findings WHERE run_id = ? AND id = ?').get(run.id, baselineId) as {
    finding: string
    severity: string
  }
  assert.equal(JSON.parse(preserved.finding).title, 'Original baseline title')
  assert.equal(preserved.severity, 'low')
  void dir
}))
