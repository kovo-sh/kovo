/**
 * Unit tests for Kovo Hunter v8 structured multi-hop funnel & telemetry extraction
 * (`scripts/benchmark-multihop.ts`) and end-to-end compatibility with
 * `scripts/certify-v8.ts` (`evaluateV8Certification`, `loadMultihopInputs`).
 *
 * Docker-free: uses Node 24 built-in `node:sqlite` (`:memory:` and temp files).
 */

import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { describe, it } from 'node:test'

import {
  aggregateMultihopTelemetry,
  buildHopDepthFunnel,
  buildMultihopReport,
  computeDepthTierBreakdown,
  computeEfficiencyMetrics,
  extractMultihopRunTelemetry,
  renderMultihopReport,
  type MultihopAppName,
  type MultihopCellReport,
  type MultihopChainVerdict,
  type MultihopRunTelemetry,
} from '../scripts/benchmark-multihop.ts'
import { emptySnapshotMeta } from '../scripts/benchmark-realistic.ts'
import {
  SCALING_TIERS,
  evaluateV8Certification,
  loadMultihopInputs,
  normalizeCell,
} from '../scripts/certify-v8.ts'

function createKovoFixtureDb(path = ':memory:'): DatabaseSync {
  const db = new DatabaseSync(path)
  db.exec(`
    CREATE TABLE runs (
      id TEXT PRIMARY KEY NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE chain_steps (
      id TEXT PRIMARY KEY NOT NULL,
      run_id TEXT NOT NULL,
      category TEXT NOT NULL,
      skills TEXT NOT NULL,
      depends_on_step_ids TEXT NOT NULL,
      depends_on_fact_ids TEXT NOT NULL,
      title TEXT NOT NULL
    );
    CREATE TABLE assignments (
      id TEXT PRIMARY KEY NOT NULL,
      run_id TEXT NOT NULL,
      phase TEXT NOT NULL,
      status TEXT NOT NULL,
      session_id TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      message TEXT NOT NULL,
      detail TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE capability_nodes (
      run_id TEXT NOT NULL,
      cap_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      promotion_status TEXT NOT NULL DEFAULT 'capability_only',
      provenance TEXT NOT NULL DEFAULT 'derived_hop',
      metadata_json TEXT NOT NULL DEFAULT '{}',
      PRIMARY KEY (run_id, cap_id)
    );
    CREATE TABLE capability_causal_edges (
      run_id TEXT NOT NULL,
      edge_id TEXT NOT NULL,
      edge_binding_kind TEXT NOT NULL,
      terminal_impact TEXT,
      metadata_json TEXT NOT NULL DEFAULT '{}',
      PRIMARY KEY (run_id, edge_id)
    );
    CREATE TABLE capability_negative_edges (
      run_id TEXT NOT NULL,
      precondition_key TEXT NOT NULL,
      target_surface_key TEXT NOT NULL,
      hypothesis_class TEXT NOT NULL,
      reason TEXT NOT NULL,
      attempt_count INTEGER NOT NULL DEFAULT 1,
      pruned INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (run_id, precondition_key, target_surface_key, hypothesis_class)
    );
    CREATE TABLE replay_specs (
      id TEXT PRIMARY KEY NOT NULL,
      run_id TEXT NOT NULL,
      finding_id TEXT NOT NULL,
      proof_kind TEXT,
      proof_verdict TEXT,
      spec TEXT NOT NULL,
      proof_receipt TEXT,
      last_verification_diff TEXT
    );
    CREATE TABLE findings (
      id TEXT PRIMARY KEY NOT NULL,
      run_id TEXT NOT NULL,
      finding_kind TEXT NOT NULL,
      verification_class TEXT NOT NULL,
      finding TEXT NOT NULL
    );
  `)
  return db
}

function makeChainVerdicts(app: string, confirmed34: number, confirmed56: number): MultihopChainVerdict[] {
  const out: MultihopChainVerdict[] = []
  for (let i = 0; i < 2; i += 1) {
    const ok = i < confirmed34
    out.push({
      chainId: `${app}-c34-${i + 1}`,
      expectedHops: 4,
      maxHopReached: ok ? 4 : 2,
      oracleObserved: ok,
      compositeReceiptConfirmed: ok,
      twoSideConfirmed: ok,
      dropReason: ok ? null : 'pivot_not_discovered',
    })
  }
  for (let i = 0; i < 2; i += 1) {
    const ok = i < confirmed56
    out.push({
      chainId: `${app}-c56-${i + 1}`,
      expectedHops: 5,
      maxHopReached: ok ? 5 : 3,
      oracleObserved: ok,
      compositeReceiptConfirmed: ok,
      twoSideConfirmed: ok,
      dropReason: ok ? null : 'budget_exhausted',
    })
  }
  return out
}

function buildCellReport(opts: {
  app: MultihopAppName
  seed: number
  mode: 'white-box' | 'grey-box'
  llm: 'agentic' | 'deterministic-no-llm'
  budgetUsd: number
  maxDurationMs: number
  costUsd: number
  durationMs: number
  confirmed34: number
  confirmed56: number
  telemetry: MultihopRunTelemetry
}): MultihopCellReport {
  const chains = makeChainVerdicts(opts.app, opts.confirmed34, opts.confirmed56)
  const confirmed = opts.confirmed34 + opts.confirmed56
  const hopFunnel = buildHopDepthFunnel(chains)
  const depthBreakdown = computeDepthTierBreakdown(chains)
  const eff = computeEfficiencyMetrics({
    confirmedChains: confirmed,
    costUsd: opts.costUsd,
    durationMs: opts.durationMs,
  })
  const phaseB = opts.telemetry.scheduler.totalPhaseBAssignments
  const reprobes = opts.telemetry.scheduler.deadEndReprobes
  const wasteRate = phaseB > 0 ? reprobes / phaseB : 0

  return {
    schemaVersion: 1,
    app: opts.app,
    sealed: false,
    seed: opts.seed,
    seedSet: 'dev',
    mode: opts.mode,
    cell: `${opts.app}-seed${opts.seed}-${opts.mode}`,
    llm: opts.llm,
    origin: 'http://127.0.0.1:41000',
    publicOrigins: ['http://127.0.0.1:41000'],
    loginPath: '/v1/auth/login',
    gitSha: 'abc123def456',
    model: opts.llm === 'agentic'
      ? { mode: 'agentic', profiles: [{ name: 'test-profile', model: 'test-model', protocol: 'responses' }] }
      : { mode: 'deterministic-no-llm', profiles: [] },
    verifierBackend: opts.llm === 'agentic' ? 'docker' : 'local-jq',
    workerSessions: opts.llm === 'agentic',
    workerSessionsDetail: opts.llm === 'agentic' ? 'docker' : 'local-jq',
    dataDirIsolated: true,
    dataDirSource: null,
    isolatedProfileNames: [],
    dataDirKept: false,
    budgetUsd: opts.budgetUsd,
    maxDurationMs: opts.maxDurationMs,
    startedAt: 1_750_000_000_000,
    endedAt: 1_750_000_000_000 + opts.durationMs,
    durationMs: opts.durationMs,
    timedOut: false,
    terminalStatus: 'complete',
    terminalPhase: 'done',
    runId: `run-${opts.app}-${opts.seed}`,
    projectId: `proj-${opts.app}`,
    chainsTotal: 4,
    chainsOracleObserved: confirmed,
    chainsCompositeConfirmed: confirmed,
    chainsConfirmed: confirmed,
    oracleOnlyCount: 0,
    receiptOnlyCount: 0,
    shortcutViolations: 0,
    modeBViolations: 0,
    recall: confirmed / 4,
    precision: 1,
    hardenedTwinsTotal: 3,
    hardenedTwinDecoyFps: 0,
    unmatchedFalsePositives: 0,
    costUsd: opts.costUsd,
    tpPerDollar: eff.tpPerDollar,
    tpPer10m: eff.tpPer10m,
    hopFunnel,
    depthBreakdown,
    chains,
    hardenedTwins: [],
    assignmentsCompleted: opts.telemetry.scheduler.workersCompleted,
    assignmentsTotal: opts.telemetry.scheduler.totalPhaseBAssignments,
    investigationCompleted: opts.telemetry.scheduler.workersCompleted,
    phaseBAssignments: phaseB,
    deadEndReprobeCount: reprobes,
    deadEndReprobeWasteRate: wasteRate,
    deadEndWastePct: opts.telemetry.scheduler.deadEndWastePct,
    frontier: {
      deadEndReprobeCount: reprobes,
      totalAssignmentsDispatched: phaseB,
      phaseBAssignments: phaseB,
      deadEndReprobeWasteRate: wasteRate,
    },
    telemetry: opts.telemetry,
    facts: 42,
    findingsPersisted: confirmed,
    findingsSubmitted: confirmed,
    compositeReceiptsExtracted: confirmed,
    endpointsDiscovered: 120,
    requestCount: 300,
    oracleEventCount: 25,
    inert: false,
    snapshot: emptySnapshotMeta(),
    resumedFrom: null,
    snapshotSkippedMs: 0,
    notes: [],
    shutdown: { engineBusy: 0, appStopped: true, canaryStopped: true },
  }
}

describe('extractMultihopRunTelemetry (SQLite fixture extraction)', () => {
  it('extracts Phase-timing, Scheduler/Dead-End-Waste, CapabilityLedger, and v8-SDK-Adoption metrics accurately with run isolation', () => {
    const db = createKovoFixtureDb()
    try {
      const t0 = 1_750_000_000_000
      const runId = 'run-main'
      const otherRunId = 'run-other'

      db.prepare('INSERT INTO runs (id, created_at) VALUES (?, ?)').run(runId, t0)
      db.prepare('INSERT INTO runs (id, created_at) VALUES (?, ?)').run(otherRunId, t0)

      // Chain steps: 1 single-route step + 2 multi-hop chain steps
      const insStep = db.prepare(
        'INSERT INTO chain_steps (id, run_id, category, skills, depends_on_step_ids, depends_on_fact_ids, title) VALUES (?, ?, ?, ?, ?, ?, ?)',
      )
      insStep.run('step-1', runId, 'broken-access-control', '["bola-bfla"]', '[]', '[]', 'Probe invoice route')
      insStep.run('step-chain-1', runId, 'chain', '["chain:tenant-pivot"]', '["step-1"]', '[]', 'Multi-hop pivot A')
      insStep.run('step-chain-2', runId, 'chain_step', '["multihop-chains"]', '[]', '["f1"]', 'Multi-hop pivot B')

      // Assignments: 1 non-investigation code_audit + 4 Phase-B investigation assignments (plus 1 in other run)
      const insAsgn = db.prepare(
        'INSERT INTO assignments (id, run_id, phase, status, session_id, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      )
      insAsgn.run('a-audit', runId, 'threat_model', 'complete', 'sess-audit', t0 + 5_000)
      insAsgn.run('a-1', runId, 'investigation', 'complete', 'sess-1', t0 + 165_000)
      insAsgn.run('a-2', runId, 'investigation', 'complete', 'sess-2', t0 + 170_000)
      insAsgn.run('a-3', runId, 'investigation', 'complete', 'sess-3', t0 + 185_000)
      insAsgn.run('a-4', runId, 'investigation', 'running', 'sess-4', t0 + 310_000)
      insAsgn.run('a-other', otherRunId, 'investigation', 'complete', 'sess-other', t0 + 10_000)

      // Structured events across Phase A -> Phase B -> verification
      const insEv = db.prepare(
        'INSERT INTO events (run_id, kind, message, detail, created_at) VALUES (?, ?, ?, ?, ?)',
      )
      insEv.run(runId, 'code_audit.started', 'Code audit started', JSON.stringify({ assignmentId: 'a-audit' }), t0 + 5_000)
      insEv.run(runId, 'code_audit.complete', 'Code audit complete', JSON.stringify({ assignmentId: 'a-audit', suspectsCount: 4 }), t0 + 95_000)
      // Complete event for non-investigation audit assignment must NOT inflate Phase B workersCompleted
      insEv.run(runId, 'worker.complete', 'Code audit completed', JSON.stringify({ assignmentId: 'a-audit' }), t0 + 95_000)
      insEv.run(
        runId,
        'deterministic_floor.summary',
        'Floor complete',
        JSON.stringify({ laneWallMs: 68_000, phaseTimings: { floorMs: 68_000, agentDispatchAt: t0 + 165_000 } }),
        t0 + 163_000,
      )
      insEv.run(runId, 'investigation.started', 'Phase B started', JSON.stringify({}), t0 + 165_000)
      insEv.run(
        runId,
        'scheduler.dispatch',
        'Dispatched 2 steps',
        JSON.stringify({ effectiveConcurrency: 3, slots: 3, dispatched: 2, selectedByLane: { lead: 2, chain: 0 } }),
        t0 + 165_000,
      )
      insEv.run(runId, 'worker.started', 'Step 1 started', JSON.stringify({ assignmentId: 'a-1', stepId: 'step-1' }), t0 + 165_000)
      insEv.run(runId, 'worker.started', 'Step 2 started', JSON.stringify({ assignmentId: 'a-2', stepId: 'step-1' }), t0 + 170_000)

      // First chain dispatch at +185s (selectedByLane.chain = 1, concurrency = 4)
      insEv.run(
        runId,
        'scheduler.dispatch',
        'Dispatched chain step',
        JSON.stringify({ effectiveConcurrency: 4, slots: 2, dispatched: 1, selectedByLane: { chain: 1 } }),
        t0 + 185_000,
      )
      insEv.run(runId, 'worker.started', 'Chain 1 started', JSON.stringify({ assignmentId: 'a-3', stepId: 'step-chain-1' }), t0 + 185_000)
      insEv.run(runId, 'worker.wall_clock_rotated', 'Worker rotated', JSON.stringify({ assignmentId: 'a-1', elapsedMs: 120_000 }), t0 + 285_000)
      insEv.run(runId, 'worker.complete', 'Step 1 completed', JSON.stringify({ assignmentId: 'a-1' }), t0 + 285_000)
      insEv.run(runId, 'worker.complete', 'Step 2 completed', JSON.stringify({ assignmentId: 'a-2' }), t0 + 300_000) // 130_000ms wall
      insEv.run(runId, 'worker.wall_clock_rotated', 'Chain 1 rotated', JSON.stringify({ assignmentId: 'a-3', elapsedMs: 160_000 }), t0 + 345_000)
      insEv.run(runId, 'worker.complete', 'Chain 1 completed', JSON.stringify({ assignmentId: 'a-3' }), t0 + 345_000)
      insEv.run(runId, 'worker.started', 'Chain 2 started', JSON.stringify({ assignmentId: 'a-4', stepId: 'step-chain-2' }), t0 + 350_000)

      // Frontier dead-end reprobe telemetry: 1 reprobe across 40 Phase-B assignments -> 2.5% waste
      insEv.run(
        runId,
        'frontier.summary',
        'Frontier wave summary',
        JSON.stringify({ totalAssignmentsDispatched: 40, deadEndReprobeCount: 1 }),
        t0 + 400_000,
      )

      // v8 SDK RPC / kovo_verify events
      insEv.run(runId, 'kovo_verify.called', 'gv 1', JSON.stringify({ callId: 'c1' }), t0 + 200_000)
      insEv.run(runId, 'verify_rpc.call', 'seal', JSON.stringify({ op: 'capability.seal', ok: true }), t0 + 201_000)
      insEv.run(runId, 'verify_rpc.call', 'seal', JSON.stringify({ op: 'capability.seal', ok: true }), t0 + 202_000)
      insEv.run(runId, 'verify_rpc.call', 'hmac', JSON.stringify({ op: 'crypto.hmacSign', ok: true }), t0 + 203_000)
      insEv.run(runId, 'verify_rpc.call', 'jwt', JSON.stringify({ op: 'crypto.jwtSign', ok: true }), t0 + 204_000)
      insEv.run(runId, 'verify_rpc.call', 'await', JSON.stringify({ op: 'async.awaitResult', ok: true }), t0 + 205_000)
      insEv.run(
        runId,
        'verify_rpc.call',
        'composite fail',
        JSON.stringify({ op: 'composite.verify', confirmed: false, failedStage: 'edge_binding_rejected' }),
        t0 + 206_000,
      )
      insEv.run(runId, 'kovo_verify.called', 'gv 2', JSON.stringify({ callId: 'c2' }), t0 + 250_000)
      insEv.run(
        runId,
        'verify_rpc.call',
        'composite ok',
        JSON.stringify({ op: 'composite.verify', confirmed: true, chainId: 'chain-1' }),
        t0 + 255_000,
      )
      insEv.run(
        runId,
        'proof_receipt.shadow_reject',
        'shadow reject',
        JSON.stringify({ reason: 'oracle_failed' }),
        t0 + 260_000,
      )
      insEv.run(
        runId,
        'kovo_verify.rejected',
        'gv reject',
        JSON.stringify({ callId: 'c3', rejectedBy: 'oracle_failed' }),
        t0 + 270_000,
      )
      insEv.run(runId, 'run.complete', 'Done', JSON.stringify({}), t0 + 600_000)

      // Noise from otherRunId must be ignored
      insEv.run(otherRunId, 'worker.wall_clock_rotated', 'Other rotated', JSON.stringify({ elapsedMs: 999_000 }), t0 + 10_000)
      insEv.run(otherRunId, 'verify_rpc.call', 'Other seal', JSON.stringify({ op: 'capability.seal', ok: true }), t0 + 10_000)

      // CapabilityLedger rows
      const insNode = db.prepare(
        'INSERT INTO capability_nodes (run_id, cap_id, kind, promotion_status, provenance) VALUES (?, ?, ?, ?, ?)',
      )
      insNode.run(runId, 'cap:hop_1:tok', 'scoped_token', 'capability_only', 'derived_hop')
      insNode.run(runId, 'cap:hop_2:key', 'signing_secret', 'capability_only', 'derived_hop')
      insNode.run(runId, 'cap:hop_3:final', 'state_handle', 'terminal_eligible', 'derived_hop')
      insNode.run(otherRunId, 'cap:hop_9:other', 'scoped_token', 'capability_only', 'derived_hop')

      const insEdge = db.prepare(
        'INSERT INTO capability_causal_edges (run_id, edge_id, edge_binding_kind, terminal_impact) VALUES (?, ?, ?, ?)',
      )
      insEdge.run(runId, 'e1', 'value_binding', null)
      insEdge.run(runId, 'e2', 'derived_crypto_binding', 'cross_tenant_write')
      insEdge.run(otherRunId, 'e-other', 'value_binding', null)

      const insNeg = db.prepare(
        'INSERT INTO capability_negative_edges (run_id, precondition_key, target_surface_key, hypothesis_class, reason, attempt_count, pruned) VALUES (?, ?, ?, ?, ?, ?, ?)',
      )
      insNeg.run(runId, 'pk1', 'POST /a', 'bfla', 'invariant_enforced_hardened', 2, 1)
      insNeg.run(runId, 'pk2', 'POST /b', 'bola', 'control_blocked_cleanly', 1, 0)
      insNeg.run(runId, 'pk3', 'POST /c', 'csrf', 'decoy_guard_verified', 2, 1)

      // Persisted composite receipt in replay_specs + findings (same chainId deduplicated!)
      const compositeReceipt = {
        chainId: 'chain-1',
        terminalVulnClass: 'maker_checker_bypass',
        replayMode: 'fresh_clean_replay',
        hops: [{ hopId: 'h1' }, { hopId: 'h2' }],
      }
      const compositeVerification = { confirmed: true, hopCount: 2 }
      db.prepare(
        'INSERT INTO replay_specs (id, run_id, finding_id, proof_kind, proof_verdict, spec, proof_receipt) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ).run(
        'rs-1',
        runId,
        'f-1',
        'agent_script',
        'confirmed',
        JSON.stringify({ compositeReceipt, compositeVerification }),
        JSON.stringify({ compositeReceipt, verification: compositeVerification }),
      )
      db.prepare(
        'INSERT INTO findings (id, run_id, finding_kind, verification_class, finding) VALUES (?, ?, ?, ?, ?)',
      ).run(
        'f-1',
        runId,
        'multi_step_chain',
        'runtime_confirmed',
        JSON.stringify({ id: 'f-1', evidence: { compositeReceipt, compositeVerification } }),
      )

      const tel = extractMultihopRunTelemetry(db, runId)

      assert.deepEqual(tel.phaseTiming, {
        codeAuditMs: 90_000,
        floorMs: 68_000,
        phaseBStartMs: 165_000,
        firstChainDispatchMs: 185_000,
        totalWallMs: 600_000,
      })

      assert.deepEqual(tel.scheduler, {
        maxEffectiveConcurrency: 4,
        workersStarted: 4,
        workersCompleted: 3,
        wallClockRotations: 2,
        maxWorkerWallMs: 160_000,
        totalPhaseBAssignments: 40,
        deadEndReprobes: 1,
        deadEndWastePct: 2.5,
      })

      assert.deepEqual(tel.capabilityLedger, {
        nodesTotal: 3,
        capabilityOnlyCount: 2,
        sealedHandlesCount: 3,
        causalEdgesCount: 2,
        negativeEdgesPrunedCount: 2,
        compositeReceiptsCount: 1,
      })

      assert.equal(tel.v8SdkAdoption.kovoVerifyCalls, 3)
      assert.equal(tel.v8SdkAdoption.sealCapabilityCalls, 2)
      assert.equal(tel.v8SdkAdoption.hmacSignCalls, 1)
      assert.equal(tel.v8SdkAdoption.jwtSignCalls, 1)
      assert.equal(tel.v8SdkAdoption.awaitAsyncCalls, 1)
      assert.equal(tel.v8SdkAdoption.proveCompositeCalls, 2)
      assert.equal(tel.v8SdkAdoption.compositeConfirmed, 1)
      assert.deepEqual(tel.v8SdkAdoption.topRejectReasons, [
        { reason: 'oracle_failed', count: 2 },
        { reason: 'edge_binding_rejected', count: 1 },
      ])
    } finally {
      db.close()
    }
  })

  it('handles minimal schemas (capability_edges + workers fallback) and empty DBs safely without throwing', () => {
    const emptyDb = new DatabaseSync(':memory:')
    try {
      const emptyTel = extractMultihopRunTelemetry(emptyDb, 'missing-run')
      assert.equal(emptyTel.phaseTiming.codeAuditMs, null)
      assert.equal(emptyTel.phaseTiming.totalWallMs, 0)
      assert.equal(emptyTel.scheduler.deadEndWastePct, 0)
      assert.equal(emptyTel.capabilityLedger.nodesTotal, 0)
      assert.equal(emptyTel.v8SdkAdoption.kovoVerifyCalls, 0)
      assert.deepEqual(emptyTel.v8SdkAdoption.topRejectReasons, [])
    } finally {
      emptyDb.close()
    }

    const simpleDb = new DatabaseSync(':memory:')
    try {
      simpleDb.exec(`
        CREATE TABLE workers (
          id TEXT PRIMARY KEY,
          run_id TEXT NOT NULL,
          status TEXT NOT NULL,
          started_at INTEGER,
          ended_at INTEGER,
          dead_end_reprobe INTEGER DEFAULT 0
        );
        CREATE TABLE capability_edges (
          run_id TEXT NOT NULL,
          kind TEXT NOT NULL,
          pruned INTEGER DEFAULT 0,
          attempt_count INTEGER DEFAULT 1
        );
      `)
      simpleDb.prepare('INSERT INTO workers VALUES (?, ?, ?, ?, ?, ?)').run('w1', 'r1', 'complete', 1_000, 46_000, 0)
      simpleDb.prepare('INSERT INTO workers VALUES (?, ?, ?, ?, ?, ?)').run('w2', 'r1', 'complete', 2_000, 62_000, 1)
      simpleDb.prepare('INSERT INTO capability_edges VALUES (?, ?, ?, ?)').run('r1', 'causal', 0, 1)
      simpleDb.prepare('INSERT INTO capability_edges VALUES (?, ?, ?, ?)').run('r1', 'negative', 1, 3)

      const tel = extractMultihopRunTelemetry(simpleDb, 'r1', { runStartedAtMs: 1_000, runEndedAtMs: 65_000 })
      assert.equal(tel.phaseTiming.totalWallMs, 64_000)
      assert.equal(tel.scheduler.workersStarted, 2)
      assert.equal(tel.scheduler.workersCompleted, 2)
      assert.equal(tel.scheduler.maxWorkerWallMs, 60_000)
      assert.equal(tel.scheduler.totalPhaseBAssignments, 2)
      assert.equal(tel.scheduler.deadEndReprobes, 1)
      assert.equal(tel.scheduler.deadEndWastePct, 50)
      assert.equal(tel.capabilityLedger.causalEdgesCount, 1)
      assert.equal(tel.capabilityLedger.negativeEdgesPrunedCount, 1)
    } finally {
      simpleDb.close()
    }
  })

  it('extracts structured v8 SDK helper counts and rejection reasons from read-only agent-sessions SQLite without leaking scripts', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'kovo-v8-telemetry-sess-'))
    try {
      const dbPath = join(tempDir, 'kovo.sqlite')
      const db = createKovoFixtureDb(dbPath)
      const t0 = 1_750_000_000_000
      db.prepare('INSERT INTO runs (id, created_at) VALUES (?, ?)').run('r-sess', t0)
      db.prepare('INSERT INTO assignments (id, run_id, phase, status, session_id, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
        'a-s1', 'r-sess', 'investigation', 'complete', 'sess-alpha', t0 + 10_000,
      )

      const sessionsDir = join(tempDir, 'agent-sessions')
      mkdirSync(sessionsDir, { recursive: true })
      const sessDb = new DatabaseSync(join(sessionsDir, 'sess-alpha.sqlite'))
      sessDb.exec('CREATE TABLE entries (id INTEGER PRIMARY KEY AUTOINCREMENT, commit_seq INTEGER NOT NULL, record TEXT NOT NULL)')
      const entry1 = {
        model: [
          {
            role: 'assistant',
            content: [
              {
                type: 'toolCall',
                id: 'tc-1',
                name: 'kovo_verify',
                arguments: {
                  runtime: 'ts',
                  script: [
                    'const h1 = await ctx.seal_capability({ exchangeId: "ex1", slot: "tok", jsonPath: "$.token" })',
                    'const sig = await ctx.hmac_sign({ secretHandle: h1, payload: "abc" })',
                    'const tok = await ctx.jwt_sign({ secretHandle: h1, claims: { role: "admin" } })',
                    'await ctx.await_async({ pollRequest: { method: "GET", path: "/status" }, predicate: { status: 200 } })',
                    'await ctx.prove_composite({ chainId: "c-live", replayMode: "fresh_clean_replay", hops: [] })',
                  ].join('\n'),
                },
              },
            ],
          },
          {
            role: 'toolResult',
            toolCallId: 'tc-1',
            content: JSON.stringify({
              confirmed: false,
              rejectedBy: 'composite_receipt',
              compositeReceipt: { chainId: 'c-live', confirmed: false, failedStage: 'attacker_provenance' },
            }),
          },
        ],
      }
      sessDb.prepare('INSERT INTO entries (commit_seq, record) VALUES (?, ?)').run(1, JSON.stringify(entry1))
      sessDb.close()

      const tel = extractMultihopRunTelemetry(db, 'r-sess', { dataDir: tempDir })
      db.close()

      assert.equal(tel.v8SdkAdoption.kovoVerifyCalls, 1)
      assert.equal(tel.v8SdkAdoption.sealCapabilityCalls, 1)
      assert.equal(tel.v8SdkAdoption.hmacSignCalls, 1)
      assert.equal(tel.v8SdkAdoption.jwtSignCalls, 1)
      assert.equal(tel.v8SdkAdoption.awaitAsyncCalls, 1)
      assert.equal(tel.v8SdkAdoption.proveCompositeCalls, 1)
      assert.equal(tel.v8SdkAdoption.compositeConfirmed, 0)
      assert.deepEqual(tel.v8SdkAdoption.topRejectReasons, [{ reason: 'attacker_provenance', count: 1 }])
    } finally {
      rmSync(tempDir, { recursive: true, force: true })
    }
  })
})

describe('Markdown Telemetry Summary & certify-v8.ts compatibility', () => {
  it('renders a compact ## Telemetry Summary section in benchmark-multihop.ts Markdown output', () => {
    const sampleTelemetry: MultihopRunTelemetry = {
      phaseTiming: {
        codeAuditMs: 88_000,
        floorMs: 54_000,
        phaseBStartMs: 145_000,
        firstChainDispatchMs: 152_000,
        totalWallMs: 600_000,
      },
      scheduler: {
        maxEffectiveConcurrency: 3,
        workersStarted: 8,
        workersCompleted: 7,
        wallClockRotations: 2,
        maxWorkerWallMs: 155_000,
        totalPhaseBAssignments: 40,
        deadEndReprobes: 1,
        deadEndWastePct: 2.5,
      },
      capabilityLedger: {
        nodesTotal: 18,
        capabilityOnlyCount: 16,
        sealedHandlesCount: 18,
        causalEdgesCount: 9,
        negativeEdgesPrunedCount: 3,
        compositeReceiptsCount: 2,
      },
      v8SdkAdoption: {
        kovoVerifyCalls: 6,
        sealCapabilityCalls: 5,
        hmacSignCalls: 2,
        jwtSignCalls: 1,
        awaitAsyncCalls: 2,
        proveCompositeCalls: 3,
        compositeConfirmed: 2,
        topRejectReasons: [{ reason: 'edge_binding_rejected', count: 1 }],
      },
    }

    const cell = buildCellReport({
      app: 'paygrid',
      seed: 1,
      mode: 'white-box',
      llm: 'agentic',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      costUsd: 2.5,
      durationMs: 600_000,
      confirmed34: 2,
      confirmed56: 0,
      telemetry: sampleTelemetry,
    })

    const report = buildMultihopReport([cell], [], 'deadbeef1234')
    assert.ok(report.telemetry)
    assert.deepEqual(aggregateMultihopTelemetry([cell]), sampleTelemetry)

    const md = renderMultihopReport(report, 'md')
    assert.match(md, /## Telemetry Summary/)
    assert.match(md, /Phase Timing/)
    assert.match(md, /Scheduler & Waste/)
    assert.match(md, /CapabilityLedger/)
    assert.match(md, /v8 SDK Adoption/)
    assert.match(md, /deadEndReprobes=1 \(2\.50%\)/)
    assert.match(md, /`edge_binding_rejected` \(1\)/)
  })

  it('feeds benchmark-multihop.ts report & meta JSON directly into scripts/certify-v8.ts (M3 PASS and FAIL on waste > 5%) without field mismatches', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'kovo-v8-certify-bridge-'))
    try {
      const devApps: readonly MultihopAppName[] = ['paygrid', 'shipforge', 'nexusiam']
      const makeTel = (deadEndReprobes: number, totalPhaseBAssignments: number): MultihopRunTelemetry => ({
        phaseTiming: {
          codeAuditMs: 85_000,
          floorMs: 50_000,
          phaseBStartMs: 140_000,
          firstChainDispatchMs: 145_000,
          totalWallMs: 600_000,
        },
        scheduler: {
          maxEffectiveConcurrency: 3,
          workersStarted: 10,
          workersCompleted: 10,
          wallClockRotations: 1,
          maxWorkerWallMs: 120_000,
          totalPhaseBAssignments,
          deadEndReprobes,
          deadEndWastePct: totalPhaseBAssignments > 0
            ? Math.round((deadEndReprobes / totalPhaseBAssignments) * 10_000) / 100
            : 0,
        },
        capabilityLedger: {
          nodesTotal: 12,
          capabilityOnlyCount: 10,
          sealedHandlesCount: 12,
          causalEdgesCount: 6,
          negativeEdgesPrunedCount: 2,
          compositeReceiptsCount: 2,
        },
        v8SdkAdoption: {
          kovoVerifyCalls: 4,
          sealCapabilityCalls: 4,
          hmacSignCalls: 1,
          jwtSignCalls: 1,
          awaitAsyncCalls: 1,
          proveCompositeCalls: 2,
          compositeConfirmed: 2,
          topRejectReasons: [],
        },
      })

      const buildM3FixtureCells = (deadEndReprobes: number, phaseBAssignments: number): MultihopCellReport[] => {
        const floorTel = makeTel(0, 0)
        const cells: MultihopCellReport[] = devApps.map(app => buildCellReport({
          app,
          seed: 1,
          mode: 'white-box',
          llm: 'deterministic-no-llm',
          budgetUsd: 0,
          maxDurationMs: 300_000,
          costUsd: 0,
          durationMs: 45_000,
          confirmed34: 0,
          confirmed56: 0,
          telemetry: floorTel,
        }))

        const agenticTel = makeTel(deadEndReprobes, phaseBAssignments)
        for (const seed of [1, 2, 3]) {
          // $2/10m: 4/12 = 33.3%
          const c2: Array<[number, number]> = [[2, 0], [1, 0], [1, 0]]
          // $5/30m: 6/12 = 50.0%
          const c5: Array<[number, number]> = [[2, 0], [1, 1], [2, 0]]
          // $15/60m: 8/12 = 66.7% (3-4 hop: 5/6 = 83.3% >= 60%, 5-6 hop: 3/6 = 50.0% >= 35%)
          const c15: Array<[number, number]> = [[2, 1], [2, 1], [1, 1]]

          devApps.forEach((app, idx) => {
            cells.push(
              buildCellReport({
                app, seed, mode: 'white-box', llm: 'agentic',
                budgetUsd: SCALING_TIERS.t2_10m.budgetUsd,
                maxDurationMs: SCALING_TIERS.t2_10m.maxDurationMs,
                costUsd: 1.6, durationMs: 450_000,
                confirmed34: c2[idx]![0], confirmed56: c2[idx]![1],
                telemetry: agenticTel,
              }),
              buildCellReport({
                app, seed, mode: 'white-box', llm: 'agentic',
                budgetUsd: SCALING_TIERS.t5_30m.budgetUsd,
                maxDurationMs: SCALING_TIERS.t5_30m.maxDurationMs,
                costUsd: 3.5, durationMs: 1_000_000,
                confirmed34: c5[idx]![0], confirmed56: c5[idx]![1],
                telemetry: agenticTel,
              }),
              buildCellReport({
                app, seed, mode: 'white-box', llm: 'agentic',
                budgetUsd: SCALING_TIERS.t15_60m.budgetUsd,
                maxDurationMs: SCALING_TIERS.t15_60m.maxDurationMs,
                costUsd: 10.5, durationMs: 2_400_000,
                confirmed34: c15[idx]![0], confirmed56: c15[idx]![1],
                telemetry: agenticTel,
              }),
            )
          })
        }
        return cells
      }

      // 1. Passing M3 report (1 / 40 = 2.5% <= 5.0% dead-end waste)
      const passCells = buildM3FixtureCells(1, 40)
      const passReport = buildMultihopReport(passCells, [], 'deadbeef1234')
      const passJsonPath = join(tempDir, 'multihop-report-pass.json')
      writeFileSync(passJsonPath, renderMultihopReport(passReport, 'json'), 'utf8')

      const loadedPass = loadMultihopInputs([passJsonPath])
      assert.equal(loadedPass.length, passCells.length)

      // Verify normalizeCell preserves exact hopFunnel, costUsd, durationMs, and waste fields
      const sampleAgentic = loadedPass.find(c => c.llm === 'agentic' && c.budgetUsd === 15)!
      const norm = normalizeCell(sampleAgentic)
      assert.equal(norm.costUsd, 10.5)
      assert.equal(norm.durationMs, 2_400_000)
      assert.equal(norm.phaseBAssignments, 40)
      assert.equal(norm.deadEndReprobeCount, 1)
      assert.equal(norm.deadEndReprobeWasteRate, 0.025)
      assert.equal(norm.hopFunnel.totalChains, 4)
      assert.equal(norm.hopFunnel.CompositeReceiptConfirmed, norm.chainsConfirmed)

      const certPass = evaluateV8Certification({ gate: 'm3', cells: loadedPass })
      assert.equal(certPass.verdict, 'PASS', JSON.stringify(certPass.failedChecks, null, 2))
      assert.equal(certPass.waste.unmeasuredCells, 0)
      assert.equal(certPass.waste.measuredCells, 27)
      assert.equal(certPass.waste.wasteRate, 0.025)
      assert.equal(certPass.checks.find(c => c.id === 'm3_dead_end_waste')?.status, 'PASS')

      // 2. Failing M3 report when dead-end reprobe waste > 5% (4 / 40 = 10.0%)
      const failCells = buildM3FixtureCells(4, 40)
      const failReport = buildMultihopReport(failCells, [], 'deadbeef1234')
      const failJsonPath = join(tempDir, 'multihop-report-fail.json')
      writeFileSync(failJsonPath, renderMultihopReport(failReport, 'json'), 'utf8')

      const certFail = evaluateV8Certification({ gate: 'm3', cells: loadMultihopInputs([failJsonPath]) })
      assert.equal(certFail.verdict, 'FAIL')
      assert.equal(certFail.waste.wasteRate, 0.1)
      assert.ok(certFail.failedChecks.some(c => c.id === 'm3_dead_end_waste'))
    } finally {
      rmSync(tempDir, { recursive: true, force: true })
    }
  })
})
