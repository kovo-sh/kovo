// v5.1 snapshot/resume acceptance tests.
//
// Covers the checkpoint contract without booting a lab app: capture -> resume round-trip keeps
// findings/facts/specs/counters, origins/ports are rebound, persona credentials are re-created
// for fresh sessions, version/age/held-out guards fail fast, snapshot files are owner-only and
// contain no secrets, and resume re-opens the run at investigation (Phase-0 never re-runs).
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import {
  existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import type { Candidate } from '../src/domain.ts'
import { createProjectPersona, resolveRunPersonas } from '../src/server/persona-vault.ts'
import { Store } from '../src/server/store.ts'
import {
  DEFAULT_SNAPSHOT_MAX_AGE_MS,
  SNAPSHOT_SCHEMA_VERSION,
  SnapshotError,
  applyRunSnapshot,
  assertSnapshotUsable,
  captureRunSnapshot,
  copySnapshotDatabase,
  currentDbMigrationVersion,
  readRunSnapshot,
  snapshotFileModes,
} from '../src/server/run-snapshot.ts'
import { parseRealisticArgs } from '../scripts/benchmark-realistic.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const OLD_ORIGIN = 'http://127.0.0.1:4100'
const NEW_ORIGIN = 'http://127.0.0.1:5200'
const OLD_CANARY = 'http://127.0.0.1:4300'
const NEW_CANARY = 'http://127.0.0.1:5400'
const PASSWORD = 'persona-super-secret-42'

interface Fixture {
  root: string
  dataDir: string
  snapshotDir: string
  storage: Store
  runId: string
  projectId: string
  personaHandle: string
  personaId: string
  candidate: Candidate
  counts: {
    endpoints: number
    facts: number
    findings: number
    replaySpecs: number
    chainSteps: number
    coverageEntries: number
    brokerExchanges: number
    boardMessages: number
    secondOrderCanaries: number
  }
}

function temporaryRoot(): string {
  return mkdtempSync(join(tmpdir(), 'kovo-snapshot-'))
}

function seedFixture(): Fixture {
  const root = temporaryRoot()
  const dataDir = join(root, 'cold-data')
  const snapshotDir = join(root, 'snapshot')
  const storage = new Store(dataDir)
  const project = storage.createProject({
    requestId: randomUUID(),
    name: 'snapshot fixture',
    seeds: [OLD_ORIGIN],
    environment: 'local-lab',
  })
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'persona_a',
    roleLabel: 'owner',
    originAllowlist: [OLD_ORIGIN],
    authKind: 'login',
    loginConfig: {
      adapter: 'json',
      email: 'persona-a@example.test',
      loginUrl: `${OLD_ORIGIN}/api/login`,
    },
    secret: PASSWORD,
    canaryMarkers: ['canary-a'],
  })
  const candidate: Candidate = {
    id: 'asset-1',
    origin: OLD_ORIGIN,
    source: 'fixture',
    thirdParty: false,
  }
  const runId = randomUUID()
  const createdAt = Date.now() - 240_000
  storage.client.prepare(
    'insert into runs (id, project_id, workspace_id, original_goal, goal, goal_revision, scope_revision, '
    + 'coordinator_id, phase, status, source_mode, capability_tier, approval_policy, approved_endpoint_patterns, '
    + 'approved_persona_ids, round_no, budget_usd, budget_requests, spent_usd, spent_tokens, spent_requests, '
    + 'turns_used, max_rps_per_origin, worker_concurrency, worker_max_turns, dynamic_step_budget, '
    + 'multi_trial_enabled, phase0_completed_at, review_plan, candidates, approved, created_at) '
    + 'values (?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?, 2, ?, ?, ?, 2, 5, 2000, 0.42, 100, 7, 3, 10, 4, 30, 48, 1, ?, null, ?, ?, ?)',
  ).run(
    runId,
    project.id,
    storage.workspace.id,
    'snapshot fixture goal',
    'snapshot fixture goal',
    'coordinator',
    'investigation',
    'running',
    'public',
    'auto_review',
    '[]',
    JSON.stringify([persona.id]),
    Date.now() - 60_000,
    JSON.stringify([candidate]),
    JSON.stringify([candidate.id]),
    createdAt,
  )
  const run = storage.run(runId)
  const worker = storage.makeWorker(run, 'investigation', candidate, 'fixture assignment', 'fixture objective')

  storage.upsertEndpoint({
    runId,
    origin: OLD_ORIGIN,
    method: 'GET',
    pathTemplate: '/api/orders/:id',
    source: 'surface_probe',
    riskScore: 72,
  })
  storage.upsertEndpoint({
    runId,
    origin: OLD_ORIGIN,
    method: 'POST',
    pathTemplate: '/api/orders',
    source: 'surface_probe',
    riskScore: 60,
  })

  const factId = randomUUID()
  storage.client.prepare(
    'insert into facts (id, run_id, assignment_id, scope_revision, goal_revision, kind, origin, summary, data, '
    + 'source_origins, evidence_ids, exchange_ids, tainted, cold_since_round, digest_id, created_at) '
    + 'values (?, ?, ?, 0, 0, ?, ?, ?, ?, ?, ?, ?, 0, null, null, ?)',
  ).run(
    factId, runId, worker.id, 'det_lead', OLD_ORIGIN,
    `Differential signal at ${OLD_ORIGIN}/api/orders/7`,
    JSON.stringify({ url: `${OLD_ORIGIN}/api/orders/7`, note: 'lead only' }),
    JSON.stringify([OLD_ORIGIN]), '[]', '[]', Date.now(),
  )

  const findingId = randomUUID()
  storage.client.prepare(
    'insert into findings (id, run_id, asset_id, goal_revision, check_id, case_id, finding_kind, replay_spec_id, '
    + 'source_origins, verification_tier, fingerprint_hash, superseded_by_finding_id, counterevidence, '
    + 'confidence_rationale, severity_change_conditions, code_locations, finding) '
    + 'values (?, ?, ?, 0, ?, ?, ?, null, ?, ?, null, null, null, null, null, null, ?)',
  ).run(
    findingId, runId, candidate.id, 'bola', 'case-1', 'multi_step_chain',
    JSON.stringify([OLD_ORIGIN]), 'runtime_confirmed',
    JSON.stringify({ id: 'finding-1', title: 'Cross-tenant order read', endpoint: `${OLD_ORIGIN}/api/orders/7` }),
  )
  storage.client.prepare(
    'insert into findings (id, run_id, asset_id, goal_revision, check_id, case_id, finding_kind, replay_spec_id, '
    + 'source_origins, verification_tier, fingerprint_hash, superseded_by_finding_id, counterevidence, '
    + 'confidence_rationale, severity_change_conditions, code_locations, finding) '
    + 'values (?, ?, ?, 0, ?, ?, ?, null, ?, ?, null, null, null, null, null, null, ?)',
  ).run(
    randomUUID(), runId, candidate.id, 'hsts', 'case-2', 'baseline_check',
    JSON.stringify([OLD_ORIGIN]), 'static_verified',
    JSON.stringify({ id: 'finding-2', title: 'Static header proof', endpoint: `${OLD_ORIGIN}/` }),
  )

  const stepId = randomUUID()
  storage.client.prepare(
    'insert into chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, category, priority, '
    + 'target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, assigned_worker_id, '
    + 'specialist_profile, trial_group_id, trial_index, source_origins, created_at, updated_at) '
    + 'values (?, ?, 0, 0, 1, ?, ?, ?, 80, ?, ?, ?, ?, ?, null, null, null, 0, ?, ?, ?)',
  ).run(
    stepId, runId, 'Verify BOLA on orders', `Replay the cross-tenant order read at ${OLD_ORIGIN}`,
    'broken-access-control', JSON.stringify([candidate.id]), '[]', JSON.stringify([factId]), '[]',
    'ready', JSON.stringify([OLD_ORIGIN]), Date.now(), Date.now(),
  )

  const specId = randomUUID()
  storage.client.prepare(
    'insert into replay_specs (id, run_id, finding_id, assignment_id, scope_revision, goal_revision, spec, '
    + 'spec_sha256, source_origins, attempt_count, verified_inline, last_verification_diff, created_at) '
    + 'values (?, ?, ?, ?, 0, 0, ?, ?, ?, 1, 0, null, ?)',
  ).run(
    specId, runId, findingId, worker.id,
    JSON.stringify({
      kind: 'single_request',
      title: 'Cross-tenant order read',
      origin: OLD_ORIGIN,
      targetOrigin: OLD_ORIGIN,
      request: { method: 'GET', pathAndQuery: '/api/orders/7', origin: OLD_ORIGIN },
    }),
    'spec-sha',
    JSON.stringify([OLD_ORIGIN]),
    Date.now(),
  )

  storage.client.prepare(
    'insert into coverage_entries (id, run_id, scope_revision, goal_revision, origin, category, status, summary, '
    + 'enforcing_control, proof_gap_reason, linked_finding_id, assignment_id, updated_at) '
    + 'values (?, ?, 0, 0, ?, ?, ?, ?, null, null, null, ?, ?)',
  ).run(randomUUID(), runId, OLD_ORIGIN, 'broken-access-control', 'reported', 'checked', worker.id, Date.now())

  storage.client.prepare(
    'insert into second_order_canaries (id, run_id, assignment_id, marker, injected_origin, injected_endpoint, '
    + 'injected_param, injected_persona, surfaced_origin, surfaced_endpoint, surfaced_persona, surfaced_exchange_id, '
    + 'status, created_at, surfaced_at) '
    + 'values (?, ?, ?, ?, ?, ?, ?, ?, null, null, null, null, ?, ?, null)',
  ).run(
    randomUUID(), runId, worker.id, 'kovo-canary-2nd-fixture', OLD_ORIGIN, '/api/orders',
    'note', 'persona_a', 'planted', Date.now(),
  )

  storage.client.prepare(
    'insert into broker_exchanges (id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins, '
    + 'method, path_and_query, persona_handle, status, media_type, req_headers, resp_headers, body_preview, '
    + 'body_artifact_id, body_sha256, secret_matches, duration_ms, created_at) '
    + 'values (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, null, ?, ?, 12, ?)',
  ).run(
    randomUUID(), runId, worker.id, OLD_ORIGIN, OLD_ORIGIN, JSON.stringify([OLD_ORIGIN]),
    'POST', '/api/orders', 'persona_a', 201, 'application/json',
    JSON.stringify({ host: '127.0.0.1:4100', authorization: '[redacted]' }),
    JSON.stringify({ location: `${OLD_ORIGIN}/api/orders/7` }),
    '{"id":7}', 'body-sha', '[]', Date.now(),
  )

  storage.client.prepare(
    'insert into board_members (id, run_id, handle, role, specialist_profile, session_id, active_assignment_id, '
    + 'state, role_affinity, last_read_seq, turns_used, posts_count, peer_hops_used, scope_revision, goal_revision, '
    + 'source_origins, created_at, updated_at) '
    + 'values (?, ?, ?, ?, null, ?, ?, ?, null, 0, 1, 1, 0, 0, 0, ?, ?, ?)',
  ).run(
    randomUUID(), runId, 'bola', 'specialist', randomUUID(), worker.id, 'working',
    JSON.stringify([OLD_ORIGIN]), Date.now(), Date.now(),
  )

  const counts = {
    endpoints: 2,
    facts: 1,
    findings: 2,
    replaySpecs: 1,
    chainSteps: 1,
    coverageEntries: 1,
    brokerExchanges: 1,
    boardMessages: 0,
    secondOrderCanaries: 1,
  }
  return {
    root,
    dataDir,
    snapshotDir,
    storage,
    runId,
    projectId: project.id,
    personaHandle: persona.handle,
    personaId: persona.id,
    candidate,
    counts,
  }
}

function countRows(storage: Store, table: string, runId: string): number {
  const row = storage.client.prepare(`select count(*) as c from ${table} where run_id = ?`).get(runId) as { c?: number }
  return Number(row?.c ?? 0)
}

function capture(fixture: Fixture) {
  return captureRunSnapshot({
    storage: fixture.storage,
    snapshotDir: fixture.snapshotDir,
    checkpoint: 'post-floor',
    target: {
      app: 'acme-saas',
      seed: 1,
      seedSet: 'dev',
      mode: 'grey-box',
      origin: OLD_ORIGIN,
      loginPath: '/api/login',
      canaryBaseUrls: [OLD_CANARY],
      projectId: fixture.projectId,
      runId: fixture.runId,
    },
    gitSha: 'deadbeefcafe',
    secrets: [{ value: PASSWORD, placeholder: '[[persona-password]]' }],
  })
}

function resumeStore(fixture: Fixture): Store {
  const target = join(fixture.root, 'resume-data')
  copySnapshotDatabase({ snapshotDir: fixture.snapshotDir, targetDir: target })
  return new Store(target)
}

// ---------------------------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------------------------

test('CLI: snapshot flags parse and are mutually exclusive with conflicting modes', () => {
  const args = parseRealisticArgs([
    '--app', 'acme-saas', '--seed', '1',
    '--snapshot-after-floor', '/tmp/snap',
  ], {})
  assert.equal(args.snapshotAfterFloorDir, '/tmp/snap')
  assert.equal(args.resumeSnapshotDir, undefined)
  assert.equal(args.snapshotMaxAgeMs, DEFAULT_SNAPSHOT_MAX_AGE_MS)
  assert.equal(args.snapshotRefresh, false)
  assert.equal(args.allowHeldoutSnapshot, false)

  const resume = parseRealisticArgs([
    '--app', 'acme-saas', '--seed', '1', '--resume-snapshot', '/tmp/snap',
    '--snapshot-max-age-ms', '60000', '--allow-heldout-snapshot',
  ], {})
  assert.equal(resume.resumeSnapshotDir, '/tmp/snap')
  assert.equal(resume.snapshotMaxAgeMs, 60_000)
  assert.equal(resume.allowHeldoutSnapshot, true)

  assert.throws(() => parseRealisticArgs(['--resume-snapshot', '/tmp/snap', '--no-llm'], {}), /live agentic model/)
  assert.throws(() => parseRealisticArgs(['--snapshot-after-floor', '/tmp/a', '--resume-snapshot', '/tmp/b'], {}), /not both/)
  assert.throws(() => parseRealisticArgs(['--snapshot-refresh'], {}), /requires --snapshot-after-floor/)
  assert.throws(() => parseRealisticArgs(['--resume-snapshot', '/tmp/a', '--reuse-recon', '/tmp/b'], {}), /drop --reuse-recon/)
})

// ---------------------------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------------------------

test('capture -> resume preserves findings/facts/specs/counters and rebinds origins', () => {
  const fixture = seedFixture()
  const source = fixture.storage
  try {
    const result = capture(fixture)
    assert.equal(result.counts.endpoints, fixture.counts.endpoints)
    assert.equal(result.counts.facts, fixture.counts.facts)
    assert.equal(result.counts.detLeads, 1)
    assert.equal(result.counts.findings, fixture.counts.findings)
    assert.equal(result.counts.runtimeConfirmed, 1)
    assert.equal(result.counts.staticVerified, 1)
    assert.equal(result.counts.replaySpecs, fixture.counts.replaySpecs)
    assert.equal(result.counts.chainSteps, fixture.counts.chainSteps)
    assert.equal(result.counts.coverageEntries, fixture.counts.coverageEntries)
    assert.equal(result.counts.brokerExchanges, fixture.counts.brokerExchanges)
    assert.equal(result.counts.secondOrderCanaries, fixture.counts.secondOrderCanaries)
    assert.equal(result.snapshot.coordinator.plannerRoundIdx, 2)
    assert.equal(result.snapshot.coordinator.scopeRevision, 0)
    assert.ok(result.snapshot.coordinator.virtualElapsedMs >= 200_000)
    assert.equal(result.snapshot.versions.dbMigrationVersion, currentDbMigrationVersion())
    assert.equal(result.snapshot.versions.snapshotSchemaVersion, SNAPSHOT_SCHEMA_VERSION)

    const loaded = readRunSnapshot(fixture.snapshotDir)
    const target = loaded.target
    target.canaryBaseUrls = [OLD_CANARY]
    const resumed = resumeStore(fixture)
    try {
      const applied = applyRunSnapshot({
        storage: resumed,
        snapshot: loaded.snapshot,
        target,
        newOrigin: NEW_ORIGIN,
        newCanaryBaseUrls: [NEW_CANARY],
        personaCredentials: [{
          handle: fixture.personaHandle,
          email: 'persona-a@example.test',
          password: PASSWORD,
        }],
      })
      assert.equal(applied.phase0Skipped, true)
      assert.ok(applied.skippedMs >= 200_000)
      assert.ok(applied.origins.rowsUpdated > 0)
      assert.equal(applied.personaSessionsRebound, 1)

      assert.equal(countRows(resumed, 'endpoints', fixture.runId), fixture.counts.endpoints)
      assert.equal(countRows(resumed, 'facts', fixture.runId), fixture.counts.facts)
      assert.equal(countRows(resumed, 'findings', fixture.runId), fixture.counts.findings)
      assert.equal(countRows(resumed, 'replay_specs', fixture.runId), fixture.counts.replaySpecs)
      assert.equal(countRows(resumed, 'chain_steps', fixture.runId), fixture.counts.chainSteps)
      assert.equal(countRows(resumed, 'coverage_entries', fixture.runId), fixture.counts.coverageEntries)
      assert.equal(countRows(resumed, 'broker_exchanges', fixture.runId), fixture.counts.brokerExchanges)
      assert.equal(countRows(resumed, 'second_order_canaries', fixture.runId), fixture.counts.secondOrderCanaries)

      const run = resumed.run(fixture.runId)
      assert.equal(run.phase, 'investigation')
      assert.equal(run.status, 'running')
      assert.ok(run.phase0CompletedAt)
      assert.equal(run.spentUsd, 0.42)
      assert.equal(run.roundNo, 2)

      const endpointOrigins = resumed.client.prepare('select origin from endpoints where run_id = ?').all(fixture.runId) as Array<{ origin: string }>
      assert.deepEqual(endpointOrigins.map(row => row.origin), [NEW_ORIGIN, NEW_ORIGIN])
      const fact = resumed.client.prepare('select origin, source_origins, summary, data from facts where run_id = ?').get(fixture.runId) as {
        origin: string; source_origins: string; summary: string; data: string
      }
      assert.equal(fact.origin, NEW_ORIGIN)
      assert.ok(!fact.source_origins.includes(OLD_ORIGIN))
      assert.ok(!fact.summary.includes(OLD_ORIGIN))
      assert.ok(!fact.data.includes(OLD_ORIGIN))
      const spec = resumed.client.prepare('select spec, source_origins from replay_specs where run_id = ?').get(fixture.runId) as {
        spec: string; source_origins: string
      }
      assert.ok(!spec.spec.includes(OLD_ORIGIN))
      assert.ok(spec.spec.includes(NEW_ORIGIN))
      assert.ok(!spec.source_origins.includes(OLD_ORIGIN))

      const exchange = resumed.client.prepare('select origin, final_origin, redirect_origins, req_headers, resp_headers from broker_exchanges where run_id = ?').get(fixture.runId) as Record<string, string>
      assert.equal(exchange.origin, NEW_ORIGIN)
      assert.equal(exchange.final_origin, NEW_ORIGIN)
      assert.ok(!exchange.redirect_origins.includes(OLD_ORIGIN))
      assert.ok(!exchange.req_headers.includes('127.0.0.1:4100'))
      assert.ok(!exchange.resp_headers.includes(OLD_ORIGIN))

      const canary = resumed.client.prepare('select injected_origin from second_order_canaries where run_id = ?').get(fixture.runId) as { injected_origin: string }
      assert.equal(canary.injected_origin, NEW_ORIGIN)

      const board = resumed.client.prepare('select state, active_assignment_id, source_origins from board_members where run_id = ?').get(fixture.runId) as {
        state: string; active_assignment_id: string | null; source_origins: string
      }
      assert.equal(board.state, 'waiting')
      assert.equal(board.active_assignment_id, null)
      assert.ok(!board.source_origins.includes(OLD_ORIGIN))

      const resumedEvent = resumed.eventsAfter(fixture.runId, 0, 500).find(event => event.kind === 'snapshot.resumed')
      assert.ok(resumedEvent)
      assert.ok(String(resumedEvent.detail.skippedMs).length > 0)
    } finally {
      resumed.close()
    }
  } finally {
    source.close()
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('resume re-creates persona credentials for fresh login sessions (mock)', () => {
  const fixture = seedFixture()
  try {
    capture(fixture)
    const resumed = resumeStore(fixture)
    try {
      const loaded = readRunSnapshot(fixture.snapshotDir)
      const target = { ...loaded.target, canaryBaseUrls: [OLD_CANARY] }
      applyRunSnapshot({
        storage: resumed,
        snapshot: loaded.snapshot,
        target,
        newOrigin: NEW_ORIGIN,
        newCanaryBaseUrls: [NEW_CANARY],
        personaCredentials: [{
          handle: fixture.personaHandle,
          email: 'persona-a@example.test',
          password: PASSWORD,
        }],
      })
      const credentialDir = join(resumed.directory, 'credentials')
      const files = readdirSync(credentialDir)
      const secretFile = files.find(name => name.startsWith('persona-') && !name.endsWith('.session'))
      assert.ok(secretFile, `expected a persona credential file, got ${files.join(', ')}`)
      assert.ok(!files.some(name => name.endsWith('.session')), 'resume must not trust a stale session file')
      const secretPath = join(credentialDir, secretFile!)
      assert.equal(statSync(secretPath).mode & 0o777, 0o600)
      const body = JSON.parse(readFileSync(secretPath, 'utf8')) as { email: string; password: string }
      assert.equal(body.password, PASSWORD)
      const resolved = resolveRunPersonas(resumed, fixture.projectId, [fixture.personaId])
      assert.equal(resolved.get(fixture.personaHandle)?.secret, PASSWORD)
      assert.equal(resolved.get(fixture.personaHandle)?.session, null)
    } finally {
      resumed.close()
    }
  } finally {
    fixture.storage.close()
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

// ---------------------------------------------------------------------------------------------
// Fail-fast guards
// ---------------------------------------------------------------------------------------------

test('schema/tool-contract mismatch fails fast with SNAPSHOT_INCOMPATIBLE', () => {
  const fixture = seedFixture()
  try {
    capture(fixture)
    const loaded = readRunSnapshot(fixture.snapshotDir)
    loaded.snapshot.versions.snapshotSchemaVersion = SNAPSHOT_SCHEMA_VERSION + 1
    assert.throws(
      () => assertSnapshotUsable(loaded, { heldOut: false, allowHeldOut: false }),
      (error: unknown) => error instanceof SnapshotError && error.code === 'SNAPSHOT_INCOMPATIBLE',
    )
    const tool = readRunSnapshot(fixture.snapshotDir)
    tool.snapshot.versions.toolContractVersion = 'v0'
    assert.throws(
      () => assertSnapshotUsable(tool, { heldOut: false, allowHeldOut: false }),
      (error: unknown) => error instanceof SnapshotError && error.code === 'SNAPSHOT_INCOMPATIBLE',
    )
  } finally {
    fixture.storage.close()
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('corrupt checksum fails fast with SNAPSHOT_CORRUPT', () => {
  const fixture = seedFixture()
  try {
    capture(fixture)
    const path = join(fixture.snapshotDir, 'snapshot.json')
    const body = JSON.parse(readFileSync(path, 'utf8')) as { counts: { facts: number } }
    body.counts.facts = 999
    writeFileSync(path, JSON.stringify(body))
    assert.throws(
      () => readRunSnapshot(fixture.snapshotDir),
      (error: unknown) => error instanceof SnapshotError && error.code === 'SNAPSHOT_CORRUPT',
    )
  } finally {
    fixture.storage.close()
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('salted held-out checkpoints are refused unless the operator opts in', () => {
  const fixture = seedFixture()
  try {
    capture(fixture)
    const loaded = readRunSnapshot(fixture.snapshotDir)
    loaded.target.seedSet = 'held-out'
    assert.throws(
      () => assertSnapshotUsable(loaded, { heldOut: true, allowHeldOut: false }),
      (error: unknown) => error instanceof SnapshotError && error.code === 'SNAPSHOT_HELDOUT_REFUSED',
    )
    const usable = assertSnapshotUsable(loaded, { heldOut: true, allowHeldOut: true })
    assert.ok(usable.ageMs >= 0)
  } finally {
    fixture.storage.close()
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('seed-set mismatch fails fast', () => {
  const fixture = seedFixture()
  try {
    capture(fixture)
    const loaded = readRunSnapshot(fixture.snapshotDir)
    loaded.target.seedSet = 'held-out'
    assert.throws(
      () => assertSnapshotUsable(loaded, { heldOut: false, allowHeldOut: true }),
      (error: unknown) => error instanceof SnapshotError && error.code === 'SNAPSHOT_INCOMPATIBLE',
    )
  } finally {
    fixture.storage.close()
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('snapshot age expiry fails fast with SNAPSHOT_EXPIRED', () => {
  const fixture = seedFixture()
  try {
    capture(fixture)
    const loaded = readRunSnapshot(fixture.snapshotDir)
    loaded.target.capturedAt = Date.now() - DEFAULT_SNAPSHOT_MAX_AGE_MS - 1_000
    assert.throws(
      () => assertSnapshotUsable(loaded, { heldOut: false, allowHeldOut: false }),
      (error: unknown) => error instanceof SnapshotError && error.code === 'SNAPSHOT_EXPIRED',
    )
    const fresh = assertSnapshotUsable(loaded, {
      heldOut: false, allowHeldOut: false, maxAgeMs: DEFAULT_SNAPSHOT_MAX_AGE_MS * 10,
    })
    assert.ok(fresh.ageMs > DEFAULT_SNAPSHOT_MAX_AGE_MS)
  } finally {
    fixture.storage.close()
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

// ---------------------------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------------------------

test('snapshot files are owner-only and contain no cookies, session values or secrets', () => {
  const fixture = seedFixture()
  try {
    capture(fixture)
    const modes = snapshotFileModes(fixture.snapshotDir)
    assert.equal(modes['.'], 0o700)
    assert.equal(modes['kovo.sqlite'], 0o600)
    assert.equal(modes['snapshot.json'], 0o600)
    assert.equal(modes['target.json'], 0o600)

    const snapshotBody = readFileSync(join(fixture.snapshotDir, 'snapshot.json'), 'utf8')
    const targetBody = readFileSync(join(fixture.snapshotDir, 'target.json'), 'utf8')
    for (const body of [snapshotBody, targetBody]) {
      assert.ok(!body.includes(PASSWORD))
      assert.ok(!/"(?:cookie|set-cookie|authorization|password|token|bearer)"\s*:/i.test(body))
      assert.ok(!body.includes('kovo-canary-'))
    }
    // The DB copy only holds rows the engine already redacted; the persona password never
    // reaches the run database at all.
    const dbBytes = readFileSync(join(fixture.snapshotDir, 'kovo.sqlite'))
    assert.equal(dbBytes.includes(Buffer.from(PASSWORD)), false)
    assert.ok(existsSync(join(fixture.snapshotDir, 'target.json')))
  } finally {
    fixture.storage.close()
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('capture redacts a registered secret that leaks into the rehydration spec', () => {
  const fixture = seedFixture()
  try {
    const secret = 'leaky-secret-value-77'
    const unsafeDir = join(fixture.root, 'unsafe-snapshot')
    const result = captureRunSnapshot({
      storage: fixture.storage,
      snapshotDir: unsafeDir,
      checkpoint: 'post-floor',
      target: {
        app: secret,
        seed: 1,
        seedSet: 'dev',
        mode: 'grey-box',
        origin: OLD_ORIGIN,
        loginPath: '/api/login',
        canaryBaseUrls: [OLD_CANARY],
        projectId: fixture.projectId,
        runId: fixture.runId,
      },
      gitSha: 'deadbeefcafe',
      secrets: [{ value: secret, placeholder: '[[secret]]' }],
    })
    assert.equal(result.target.app, '[[secret]]')
    const body = readFileSync(join(unsafeDir, 'target.json'), 'utf8')
    assert.ok(!body.includes(secret))
    assert.ok(body.includes('[[secret]]'))
  } finally {
    fixture.storage.close()
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('resume does not re-run Phase-0: phase gate is preserved and no discovery is recorded', () => {
  const fixture = seedFixture()
  try {
    const captured = capture(fixture)
    const loaded = readRunSnapshot(fixture.snapshotDir)
    const resumed = resumeStore(fixture)
    try {
      const applied = applyRunSnapshot({
        storage: resumed,
        snapshot: loaded.snapshot,
        target: { ...loaded.target, canaryBaseUrls: [OLD_CANARY] },
        newOrigin: NEW_ORIGIN,
        newCanaryBaseUrls: [NEW_CANARY],
        personaCredentials: [{
          handle: fixture.personaHandle,
          email: 'persona-a@example.test',
          password: PASSWORD,
        }],
      })
      assert.equal(applied.phase0Skipped, true)
      assert.equal(applied.skippedMs, captured.snapshot.coordinator.virtualElapsedMs)
      const run = resumed.run(fixture.runId)
      assert.equal(run.phase0CompletedAt, captured.snapshot.coordinator.phase0CompletedAt)
      assert.equal(run.phase, 'investigation')
      assert.equal(run.status, 'running')
      const events = resumed.eventsAfter(fixture.runId, 0, 500)
      assert.equal(events.some(event => event.kind.startsWith('phase0.')), false)
      assert.equal(events.some(event => event.kind === 'discovery.started'), false)
    } finally {
      resumed.close()
    }
  } finally {
    fixture.storage.close()
    rmSync(fixture.root, { recursive: true, force: true })
  }
})
