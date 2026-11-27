import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { test } from 'node:test'
import {
  formatReplayDiffReport,
  replayVerifyCorpus,
  resignTranscriptForReplay,
  sanitizeReplayReason,
  type VerifyCorpusCapture,
} from '../scripts/replay-v8-receipts.ts'
import {
  discoverCellDatabases,
  evaluateWatchdogAlerts,
  formatLivePeekReport,
  peekLiveOutDir,
  sanitizeLiveSignature,
} from '../scripts/peek-v8-live.ts'
import {
  sha256Hex,
  signHostRecord,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { captureVerifyCorpusRecord } from '../src/server/exec-worker-runner.ts'

const ORIGIN = 'https://app.example.test'
const TEST_KEY = 'unit-test-signing-key-0123456789'

function makeEntry(
  id: string,
  opts: {
    method: string
    pathAndQuery: string
    status: number
    arm: 'control' | 'probe' | 'setup'
    actorPersona: string
    actorTenant: string
    timestampMs: number
    body?: string
    json?: unknown
    requestHeaders?: Record<string, string>
    responseHeaders?: Record<string, string>
    emittedCapabilities?: string[]
    consumedCapabilities?: string[]
    observedResponseDigests?: string[]
    injectedRequestDigests?: string[]
    cleanSession?: boolean
  },
): HostTranscriptEntry {
  return {
    exchangeId: id,
    origin: ORIGIN,
    timestampMs: opts.timestampMs,
    actorPersona: opts.actorPersona,
    actorTenant: opts.actorTenant,
    actorPrivilege: 'member',
    cleanSession: opts.cleanSession ?? true,
    ...(opts.emittedCapabilities ? { emittedCapabilities: opts.emittedCapabilities } : {}),
    ...(opts.consumedCapabilities ? { consumedCapabilities: opts.consumedCapabilities } : {}),
    ...(opts.observedResponseDigests ? { observedResponseDigests: opts.observedResponseDigests } : {}),
    ...(opts.injectedRequestDigests ? { injectedRequestDigests: opts.injectedRequestDigests } : {}),
    step: {
      id,
      arm: opts.arm,
      actor: { handle: opts.actorPersona, role: 'member', tenant: opts.actorTenant, auth: 'bearer', sameSite: null },
      method: opts.method,
      pathAndQuery: opts.pathAndQuery,
      route: opts.pathAndQuery.split('?')[0] ?? opts.pathAndQuery,
      status: opts.status,
      ...(opts.body !== undefined ? { body: opts.body } : {}),
      ...(opts.json !== undefined ? { json: opts.json } : {}),
      ...(opts.requestHeaders ? { requestHeaders: opts.requestHeaders } : {}),
      ...(opts.responseHeaders ? { responseHeaders: opts.responseHeaders } : {}),
    },
  }
}

function buildValidTwoHopBundle(): { receipt: CompositeProofReceipt; transcript: HostSignedTranscript } {
  const tokenVal = 'derived_export_handle_alpha_9981'
  const tokenDigest = sha256Hex(tokenVal)
  const capHandle = 'cap:hop_1:export_token'

  const ctrl = makeEntry('ex_ctrl_1', {
    method: 'GET',
    pathAndQuery: '/api/tenants/org_b/exports/42',
    status: 403,
    arm: 'control',
    actorPersona: 'member_a',
    actorTenant: 'org_a',
    timestampMs: 1000,
    json: { error: 'forbidden' },
  })
  const hop1 = makeEntry('ex_hop1_1', {
    method: 'POST',
    pathAndQuery: '/api/exports/mint',
    status: 200,
    arm: 'setup',
    actorPersona: 'member_a',
    actorTenant: 'org_a',
    timestampMs: 2000,
    emittedCapabilities: [capHandle],
    observedResponseDigests: [tokenDigest],
    json: { exportToken: tokenVal },
  })
  const hop2 = makeEntry('ex_hop2_1', {
    method: 'GET',
    pathAndQuery: '/api/tenants/org_b/exports/42',
    status: 200,
    arm: 'probe',
    actorPersona: 'member_a',
    actorTenant: 'org_a',
    timestampMs: 3000,
    consumedCapabilities: [capHandle],
    injectedRequestDigests: [tokenDigest],
    json: { tenantId: 'org_b', invoiceTotal: 91250, privateEmail: 'billing@org-b.example' },
  })

  const receipt: CompositeProofReceipt = {
    chainId: 'chain-export-01',
    terminalVulnClass: 'idor',
    replayMode: 'fresh_clean_replay',
    hops: [
      {
        hopId: 'hop_1',
        surface: 'http',
        target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/exports/mint' },
        exchangeIds: ['ex_hop1_1'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Minted export capability token',
        producedCapabilities: [capHandle],
        consumedCapabilities: [],
      },
      {
        hopId: 'hop_2',
        surface: 'http',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/tenants/org_b/exports/42' },
        exchangeIds: ['ex_hop2_1'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Retrieved foreign tenant org_b export record using minted token',
        producedCapabilities: [],
        consumedCapabilities: [capHandle],
      },
    ],
    causalEdges: [
      {
        kind: 'value_binding',
        fromHopId: 'hop_1',
        toHopId: 'hop_2',
        capabilityHandle: capHandle,
        valueDigest: tokenDigest,
        sourceExchangeId: 'ex_hop1_1',
        targetExchangeId: 'ex_hop2_1',
      },
    ],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Cross-tenant export readback for org_b',
      summary: 'Cross-tenant export readback for org_b',
      terminalExchangeId: 'ex_hop2_1',
      preChainControlExchangeIds: ['ex_ctrl_1'],
      postChainReadbackExchangeIds: [],
    },
  }

  return {
    receipt,
    transcript: { entries: [ctrl, hop1, hop2] },
  }
}

function buildFailingNoControlBundle(): { receipt: CompositeProofReceipt; transcript: HostSignedTranscript } {
  const valid = buildValidTwoHopBundle()
  return {
    receipt: {
      ...valid.receipt,
      chainId: 'chain-missing-ctrl-02',
      terminalImpact: {
        ...valid.receipt.terminalImpact,
        preChainControlExchangeIds: [],
      },
    },
    transcript: valid.transcript,
  }
}

test('replay-v8-receipts classifies flipped, regressed, still-passing, still-failing and scrubs secrets', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-replay-corpus-'))
  try {
    const valid = buildValidTwoHopBundle()
    const failing = buildFailingNoControlBundle()

    const signedEntries = (valid.transcript.entries ?? []).map(e => ({
      ...e,
      hostSignature: signHostRecord(e, TEST_KEY),
    }))

    // 1. FLIPPED FAIL -> PASS (without signingKey -> auto re-signed)
    const flippedCap: VerifyCorpusCapture = {
      schemaVersion: 1,
      app: 'demo-app',
      runId: 'run-1',
      receipt: valid.receipt,
      transcript: valid.transcript,
      verifyOptions: { attackerPersonas: ['member_a'] },
      verdict: {
        confirmed: false,
        rejectedBy: 'terminal_impact',
        reason: 'Missing clean denied control before fix Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload12345.sig',
      },
    }

    // 2. STILL PASSING (uses native signingKey directly without re-signing)
    const stillPassCap: VerifyCorpusCapture = {
      schemaVersion: 1,
      app: 'demo-app',
      runId: 'run-2',
      receipt: valid.receipt,
      transcript: { entries: signedEntries },
      signingKey: TEST_KEY,
      verifyOptions: { attackerPersonas: ['member_a'] },
      verdict: { confirmed: true, reason: 'Confirmed' },
    }

    // 3. REGRESSED PASS -> FAIL (TP regression!)
    const regressedCap: VerifyCorpusCapture = {
      schemaVersion: 1,
      app: 'demo-app',
      runId: 'run-3',
      expected: { confirmed: true, side: 'tp' },
      receipt: failing.receipt,
      transcript: failing.transcript,
      verifyOptions: { attackerPersonas: ['member_a'] },
      verdict: { confirmed: true, reason: 'Previously confirmed' },
    }

    // 4. STILL FAILING (with sensitive body/token in original reason)
    const stillFailCap: VerifyCorpusCapture = {
      schemaVersion: 1,
      app: 'demo-app',
      runId: 'run-4',
      receipt: failing.receipt,
      transcript: failing.transcript,
      verifyOptions: { attackerPersonas: ['member_a'] },
      verdict: {
        confirmed: false,
        rejectedBy: 'terminal_impact_unproven',
        reason: 'Missing clean denied control body={"secret":"top_secret_val_999"}',
      },
    }

    writeFileSync(join(dir, '01-flipped.json'), JSON.stringify(flippedCap))
    writeFileSync(join(dir, '02-still-pass.json'), JSON.stringify(stillPassCap))
    writeFileSync(join(dir, '03-regressed.json'), JSON.stringify(regressedCap))
    writeFileSync(join(dir, '04-still-fail.json'), JSON.stringify(stillFailCap))

    const report = await replayVerifyCorpus({ dir })
    assert.equal(report.totalLoaded, 4)
    assert.equal(report.totalReplayed, 4)
    assert.equal(report.parseErrors.length, 0)
    assert.equal(report.flippedFailToPass.count, 1)
    assert.equal(report.flippedFailToPass.cases[0]?.resigned, true)
    assert.equal(report.stillPassing.count, 1)
    assert.equal(report.regressedPassToFail.count, 1)
    assert.equal(report.regressedPassToFail.tpCount, 1)
    assert.equal(report.stillFailing.count, 1)
    assert.equal(report.stillFailing.histogram.length, 1)

    const formatted = formatReplayDiffReport(report)
    assert.match(formatted, /FLIPPED FAIL -> PASS\s*:\s*1/)
    assert.match(formatted, /REGRESSED PASS -> FAIL:\s*1.*1 TP regression/)
    assert.match(formatted, /STILL FAILING\s*:\s*1/)
    assert.doesNotMatch(formatted, /eyJhbGciOiJIUzI1NiJ9/)
    assert.doesNotMatch(formatted, /top_secret_val_999/)

    // --only-failed skips the 2 originally passing captures
    const onlyFailedReport = await replayVerifyCorpus({ dir, onlyFailed: true })
    assert.equal(onlyFailedReport.totalLoaded, 4)
    assert.equal(onlyFailedReport.skippedPassing, 2)
    assert.equal(onlyFailedReport.totalReplayed, 2)
    assert.equal(onlyFailedReport.flippedFailToPass.count, 1)
    assert.equal(onlyFailedReport.stillFailing.count, 1)
    assert.equal(onlyFailedReport.regressedPassToFail.count, 0)

    // Sanity check sanitizer and resign helper
    const scrubbed = sanitizeReplayReason('Error token=sk-live-secret123456789 body={"raw":"html"}')
    assert.doesNotMatch(scrubbed, /sk-live-secret/)
    assert.doesNotMatch(scrubbed, /"raw"/)
    const resigned = resignTranscriptForReplay(valid.transcript, TEST_KEY)
    assert.equal(resigned.entries?.every(e => typeof e.hostSignature === 'string' && e.hostSignature.length === 64), true)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('captureVerifyCorpusRecord is opt-in, strips credentials/tokens, and replays cleanly', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-capture-hook-'))
  try {
    const { receipt, transcript } = buildValidTwoHopBundle()
    // Attach sensitive auth headers, JWTs, and a named secret to verify zero leakage on disk
    const dirtyTranscript: HostSignedTranscript = {
      entries: (transcript.entries ?? []).map(e => ({
        ...e,
        hostSignature: 'deadbeef'.repeat(8),
        step: {
          ...e.step,
          requestHeaders: {
            Authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.sensitivePayload99.sig99',
            Cookie: 'session_id=super_secret_cookie_val',
            'X-Custom-Safe': 'ok',
          },
          responseHeaders: {
            'Set-Cookie': 'sid=secret_set_cookie_val; HttpOnly',
            'Content-Type': 'application/json',
          },
        },
      })),
    }

    // Without env or captureDir -> strictly no-op
    const prevEnv = process.env.KOVO_CAPTURE_VERIFY_CORPUS_DIR
    delete process.env.KOVO_CAPTURE_VERIFY_CORPUS_DIR
    try {
      const skipped = captureVerifyCorpusRecord({
        app: 'demo-app',
        runId: 'run-noop',
        receipt,
        verification: {
          confirmed: true,
          chainId: receipt.chainId,
          terminalVulnClass: receipt.terminalVulnClass,
          replayMode: receipt.replayMode,
          modeBVerified: false,
          hopCount: 2,
          verifiedEdges: [],
          reason: 'Confirmed',
        },
        hostTranscript: dirtyTranscript,
      })
      assert.equal(skipped, null)
    } finally {
      if (prevEnv !== undefined) process.env.KOVO_CAPTURE_VERIFY_CORPUS_DIR = prevEnv
    }

    // With captureDir -> writes sanitized capture that replays cleanly
    const written = captureVerifyCorpusRecord({
      captureDir: dir,
      app: 'demo-app',
      runId: 'run-capture-1',
      assignmentId: 'asgn-1',
      receipt,
      verification: {
        confirmed: false,
        chainId: receipt.chainId,
        terminalVulnClass: receipt.terminalVulnClass,
        replayMode: receipt.replayMode,
        modeBVerified: false,
        hopCount: 2,
        verifiedEdges: [],
        failedStage: 'terminal_impact',
        rejectedBy: 'terminal_impact_unproven',
        reason: 'Rejected with secret_needle_xyz',
      },
      hostTranscript: dirtyTranscript,
      secrets: [{ value: 'secret_needle_xyz', placeholder: '[redacted:test]' }],
    })
    assert.ok(written, 'expected capture file to be written')
    const rawDisk = readFileSync(written!, 'utf8')
    assert.doesNotMatch(rawDisk, /eyJhbGciOiJIUzI1NiJ9/)
    assert.doesNotMatch(rawDisk, /super_secret_cookie_val/)
    assert.doesNotMatch(rawDisk, /secret_set_cookie_val/)
    assert.doesNotMatch(rawDisk, /secret_needle_xyz/)
    assert.doesNotMatch(rawDisk, /deadbeefdeadbeef/)
    assert.match(rawDisk, /"X-Custom-Safe": "ok"/)

    // Replay the captured file offline -> flips FAIL -> PASS with 0 errors
    const report = await replayVerifyCorpus({ dir })
    assert.equal(report.totalReplayed, 1)
    assert.equal(report.flippedFailToPass.count, 1)
    assert.equal(report.regressedPassToFail.count, 0)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

function seedCellDb(
  dbPath: string,
  spec: {
    runId: string
    phase: string
    status: string
    costUsd: number
    createdAtMs: number
    assignments: Array<{ id: string; status: string; sessionId?: string }>
    findings: Array<{ id: string; status: string; kind: string; cwe: string; route: string }>
    events: Array<{ kind: string; detail: Record<string, unknown>; createdAtMs: number }>
  },
): void {
  mkdirSync(join(dbPath, '..'), { recursive: true })
  const db = new DatabaseSync(dbPath)
  try {
    db.exec('PRAGMA journal_mode = WAL')
    db.exec(`
      CREATE TABLE runs (
        id TEXT PRIMARY KEY, phase TEXT, status TEXT,
        spent_usd REAL, turns_used INTEGER, spent_requests INTEGER, created_at INTEGER
      );
      CREATE TABLE assignments (
        id TEXT PRIMARY KEY, run_id TEXT, status TEXT, session_id TEXT
      );
      CREATE TABLE findings (
        id TEXT PRIMARY KEY, run_id TEXT, status TEXT, finding_kind TEXT, check_id TEXT, cwe TEXT, finding TEXT
      );
      CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, kind TEXT, detail TEXT, created_at INTEGER
      );
    `)
    db.prepare('INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?)').run(
      spec.runId, spec.phase, spec.status, spec.costUsd, 42, 180, spec.createdAtMs,
    )
    const insAsgn = db.prepare('INSERT INTO assignments VALUES (?, ?, ?, ?)')
    for (const a of spec.assignments) {
      insAsgn.run(a.id, spec.runId, a.status, a.sessionId ?? '')
    }
    const insFind = db.prepare('INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?)')
    for (const f of spec.findings) {
      insFind.run(
        f.id,
        spec.runId,
        f.status,
        f.kind,
        f.kind,
        f.cwe,
        JSON.stringify({ status: f.status, kind: f.kind, cwe: f.cwe, route: f.route }),
      )
    }
    const insEv = db.prepare('INSERT INTO events (run_id, kind, detail, created_at) VALUES (?, ?, ?, ?)')
    for (const e of spec.events) {
      insEv.run(spec.runId, e.kind, JSON.stringify(e.detail), e.createdAtMs)
    }
  } finally {
    db.close()
  }
}

test('peek-v8-live inspects cell SQLite DBs read-only, scrubs output, and flags ABORT_RECOMMENDED', () => {
  const root = mkdtempSync(join(tmpdir(), 'kovo-peek-live-'))
  try {
    const nowMs = 1_700_000_600_000
    const sixMinAgo = nowMs - 6 * 60_000

    // Healthy WB cell
    const healthyDb = join(root, 'wb', 'data', 'alpha-s42', 'kovo.sqlite')
    seedCellDb(healthyDb, {
      runId: 'run-wb-1',
      phase: 'investigation',
      status: 'running',
      costUsd: 0.425,
      createdAtMs: sixMinAgo,
      assignments: [
        { id: 'a1', status: 'complete' },
        { id: 'a2', status: 'complete' },
        { id: 'a3', status: 'running' },
      ],
      findings: [
        {
          id: 'f1',
          status: 'confirmed',
          kind: 'cross_tenant_export',
          cwe: 'CWE-639',
          route: '/api/exports/42?token=secret_query_tok_123',
        },
        {
          id: 'f2',
          status: 'pending',
          kind: 'unconfirmed_note',
          cwe: 'CWE-200',
          route: '/api/health',
        },
      ],
      events: [
        {
          kind: 'composite.rejected',
          detail: {
            rejectedBy: 'edge_binding',
            reason: 'Missing capability binding Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.leak.sig body={"html":"raw"}',
          },
          createdAtMs: sixMinAgo + 120_000,
        },
      ],
    })

    // Unhealthy GB cell: systemic terminal_class_unmapped + high worker failure rate
    const unhealthyDb = join(root, 'gb', 'data', 'beta-s42', 'kovo.sqlite')
    seedCellDb(unhealthyDb, {
      runId: 'run-gb-1',
      phase: 'investigation',
      status: 'running',
      costUsd: 0.88,
      createdAtMs: sixMinAgo,
      assignments: [
        { id: 'b1', status: 'failed' },
        { id: 'b2', status: 'failed' },
        { id: 'b3', status: 'complete' },
      ],
      findings: [],
      events: [
        { kind: 'composite.rejected', detail: { rejectedBy: 'terminal_class_unmapped', reason: 'terminal_class_unmapped: foo_bar' }, createdAtMs: sixMinAgo + 60_000 },
        { kind: 'composite.rejected', detail: { rejectedBy: 'terminal_class_unmapped', reason: 'terminal_class_unmapped: foo_bar' }, createdAtMs: sixMinAgo + 90_000 },
        { kind: 'composite.rejected', detail: { rejectedBy: 'terminal_class_unmapped', reason: 'terminal_class_unmapped: foo_bar' }, createdAtMs: sixMinAgo + 120_000 },
        { kind: 'agent.verify_checkpoint_blocked', detail: { rejectedBy: 'checkpoint_blocked', reason: 'CIRCUIT BREAKER checkpoint_only' }, createdAtMs: sixMinAgo + 150_000 },
      ],
    })

    const discovered = discoverCellDatabases([join(root, 'wb'), join(root, 'gb')])
    assert.equal(discovered.length, 2)

    const report = peekLiveOutDir({
      outDirs: [join(root, 'wb'), join(root, 'gb')],
      nowMs,
    })

    assert.equal(report.cellsFound, 2)
    assert.equal(report.totalConfirmedFindings, 1)
    assert.equal(report.abortRecommended, true)
    assert.deepEqual(report.abortCells, ['gb/beta-s42'])

    const wbCell = report.cells.find(c => c.cell === 'wb/alpha-s42')
    assert.ok(wbCell)
    assert.equal(wbCell.phase, 'investigation')
    assert.equal(wbCell.costUsd, 0.425)
    assert.equal(wbCell.elapsedMin, 6)
    assert.equal(wbCell.abortRecommended, false)
    assert.deepEqual(wbCell.confirmedFindings, [
      { kind: 'cross_tenant_export', cwe: 'CWE-639', route: '/api/exports/42' },
    ])
    assert.equal(wbCell.topRejectReasons.length, 1)
    assert.doesNotMatch(wbCell.topRejectReasons[0]!.signature, /eyJhbGciOiJIUzI1NiJ9/)
    assert.doesNotMatch(wbCell.topRejectReasons[0]!.signature, /"html"/)

    const gbCell = report.cells.find(c => c.cell === 'gb/beta-s42')
    assert.ok(gbCell)
    assert.equal(gbCell.abortRecommended, true)
    assert.equal(gbCell.systemicErrors.terminal_class_unmapped, 3)
    assert.equal(gbCell.systemicErrors.checkpoint_blocked, 1)
    assert.ok(gbCell.workers.failureRate > 0.5)
    assert.ok(gbCell.abortReasons.some(r => r.includes('terminal_class_unmapped=3')))
    assert.ok(gbCell.abortReasons.some(r => r.includes('workerFailureRate=')))

    const rendered = formatLivePeekReport(report)
    assert.match(rendered, /ABORT_RECOMMENDED/)
    assert.match(rendered, /CWE-639/)
    assert.doesNotMatch(rendered, /secret_query_tok_123/)
    assert.doesNotMatch(rendered, /eyJhbGciOiJIUzI1NiJ9/)

    // Configurable thresholds check
    const relaxed = evaluateWatchdogAlerts(
      { terminal_class_unmapped: 2, composite_schema: 0, checkpoint_blocked: 0 },
      { total: 3, running: 0, completed: 1, failed: 2, finished: 3, failureRate: 0.6667 },
      { systemicThreshold: 5, workerFailureRateThreshold: 0.75, minFinishedWorkers: 2 },
    )
    assert.equal(relaxed.abortRecommended, false)

    const sig = sanitizeLiveSignature('Schema error password=super_secret_pw body=<html>secret</html>')
    assert.doesNotMatch(sig, /super_secret_pw/)
    assert.doesNotMatch(sig, /<html>secret/)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
