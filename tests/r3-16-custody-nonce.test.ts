/**
 * R3-16 Class-Level Guards: Evidence Custody by Type, Mandatory Registry (Zero Fallback),
 * Per-Run HMAC Nonce Ledger, Restart Persistence (Cited-Only), and Host-Assigned Arm Provenance.
 *
 * Pure behavioral tests — ZERO source-text file reads or regex assertions.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import * as compositeModule from '../src/server/composite-receipt.ts'
import {
  registerDefaultCompositeOracleEvaluator,
  UnregisteredOracleEvaluatorError,
  verifyCompositeReceipt,
} from '../src/server/composite-receipt.ts'
import {
  constructHostEvidence,
  HOST_CUSTODY_RECEIPT_ALLOWLIST,
  isHostEvidence,
  WORKER_STRIPPED_RECEIPT_SCALARS,
  type HostEvidence,
} from '../src/server/evidence-provenance.ts'
import {
  HostFactLog,
  resolveCanonicalArmWithProvenance,
} from '../src/server/host-fact-log.ts'
import {
  NON_NONCE_ORACLE_BINDING_KINDS,
  NonceLedger,
  SqliteNonceLedgerPersistence,
} from '../src/server/nonce-ledger.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import {
  buildProofReceipt,
  HostMintedOracle,
  proofReceiptSchema,
  verifyHostEvidence,
  verifyReceipt,
  type ReceiptTranscriptEntry,
} from '../src/server/proof-receipt.ts'
import { runAllRunDisposers } from '../src/server/run-disposers.ts'
import { Store } from '../src/server/store.ts'
import {
  defaultTerminalOracleRegistry,
  evaluateTerminalOracle,
  registerDefaultTerminalOracleRegistry,
  sanitizeSingleHopReceiptForHostCustody,
  TerminalOracleRegistry,
  UnregisteredTerminalOracleError,
} from '../src/server/terminal-oracle-registry.ts'
import { TranscriptStore } from '../src/server/verify-claims.ts'
import {
  handleProveAccessBoundary,
  handleProveDifferential,
  handleProveInjection,
  type ProveHandlerHost,
  type ProveHttpExchangeStamps,
} from '../src/server/verify-prove-handlers.ts'

const ORIGIN = 'https://app.example.invalid'
const OTHER_ORIGIN = 'https://other.example.invalid'

function mkStep(overrides: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'route' | 'status'>): ImpactStep {
  return {
    pathAndQuery: overrides.route,
    actor: { handle: 'alice', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null },
    ...overrides,
  }
}

// ============================================================================
// Test 1: Mandatory Registry & Zero Unsanitized Fallback
// ============================================================================

test('R3-16 Test 1: unregistered registry throws fail-closed and no fallbackOracleEvaluator export exists', () => {
  assert.equal('fallbackOracleEvaluator' in compositeModule, false, 'composite-receipt.ts must not export fallbackOracleEvaluator')

  const log = new HostFactLog()
  log.recordExchange({
    seq: 1, exchangeId: 'ctl', arm: 'control', method: 'GET', origin: ORIGIN,
    pathAndQuery: '/api/items/1', status: 403, actor: 'alice', actorRoleLabel: 'member (acme)',
    rawResponseBody: '{"error":"forbidden"}', timestampMs: 1_000, cleanSession: true,
  })
  log.recordExchange({
    seq: 2, exchangeId: 'prb', arm: 'probe', method: 'GET', origin: ORIGIN,
    pathAndQuery: '/api/items/1', status: 200, actor: 'alice', actorRoleLabel: 'member (acme)',
    rawResponseBody: '{"id":"1","tenant_id":"globex","secret":"top"}', timestampMs: 1_100, cleanSession: true,
  })
  const receipt = buildProofReceipt({
    vulnClass: 'bola',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items/1' },
    exchangeIds: ['ctl', 'prb'],
    claimedDelta: 'Unauthorized cross-tenant read.',
  })

  // Unregistered empty TerminalOracleRegistry throws on single_hop and v8_family
  const emptyRegistry = new TerminalOracleRegistry({ registerDefaults: false })
  assert.throws(
    () => emptyRegistry.evaluate(log, { kind: 'single_hop', receipt }),
    UnregisteredTerminalOracleError,
    'empty TerminalOracleRegistry must throw on single_hop evaluation',
  )
  assert.throws(
    () => emptyRegistry.evaluate(log, { kind: 'v8_family', family: 'economic_conservation', rawInput: {} }),
    UnregisteredTerminalOracleError,
    'empty TerminalOracleRegistry must throw on v8_family evaluation',
  )

  // Unregistered global default registry throws in both evaluateTerminalOracle and verifyCompositeReceipt
  try {
    registerDefaultTerminalOracleRegistry(null)
    assert.throws(
      () => evaluateTerminalOracle(log, { kind: 'single_hop', receipt }),
      UnregisteredTerminalOracleError,
      'evaluateTerminalOracle must throw when default registry is unregistered',
    )
    registerDefaultCompositeOracleEvaluator(null)
    const compositeReceipt = {
      chainId: 'r3-16-unregistered-check',
      terminalVulnClass: 'bola',
      hops: [{
        hopId: 'h1',
        surface: 'http',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items/1' },
        exchangeIds: ['ctl', 'prb'],
        claimedDelta: 'Embedded single-hop receipt without registered evaluator.',
        proofReceipt: receipt,
      }],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'h1',
        terminalExchangeId: 'prb',
        summary: 'Embedded receipt requires registered composite oracle evaluator.',
        preChainControlExchangeIds: ['ctl'],
        proofReceipt: receipt,
      },
      replayMode: 'fresh_clean_replay',
    }
    assert.throws(
      () => verifyCompositeReceipt(compositeReceipt, log.toHostSignedTranscript(), { factLog: log }),
      UnregisteredOracleEvaluatorError,
      'verifyCompositeReceipt must throw fail-closed instead of falling back to unsanitized verifyReceipt',
    )
  } finally {
    registerDefaultTerminalOracleRegistry(defaultTerminalOracleRegistry)
  }
})

// ============================================================================
// Test 2: Strict Custody Allowlist Enumeration & Sealed HostEvidence
// ============================================================================

test('R3-16 Test 2: allowlist enumerates every receipt field and strips 100% of worker scalars from HostEvidence', () => {
  const schemaKeys = Object.keys(proofReceiptSchema.shape).sort()
  const accounted = new Set<string>([...HOST_CUSTODY_RECEIPT_ALLOWLIST, ...WORKER_STRIPPED_RECEIPT_SCALARS])
  for (const key of schemaKeys) {
    assert.ok(accounted.has(key), `proofReceiptSchema field "${key}" must be classified in allowlist or stripped list`)
  }

  const log = new HostFactLog()
  log.recordExchange({
    seq: 2, exchangeId: 'ex-2', arm: 'probe', method: 'PATCH', origin: ORIGIN,
    pathAndQuery: '/api/account', status: 200, actor: 'alice', actorRoleLabel: 'member (acme)',
    rawRequestBody: '{"note":"ok"}', rawResponseBody: '{"note":"ok","balance":90}', timestampMs: 2_000,
  })
  log.recordExchange({
    seq: 1, exchangeId: 'ex-1', arm: 'control', method: 'GET', origin: ORIGIN,
    pathAndQuery: '/api/account', status: 200, actor: 'alice', actorRoleLabel: 'member (acme)',
    rawResponseBody: '{"note":"old","balance":100}', timestampMs: 1_000,
  })

  // Construct a receipt carrying EVERY worker scalar plus an injected unknown property
  const workerPolluted = {
    ...buildProofReceipt({
      vulnClass: 'mass_assignment',
      target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/api/account', param: 'note' },
      exchangeIds: ['ex-2', 'ex-1'], // intentionally reversed by worker
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: 'Worker-claimed mass assignment.',
      oracleEvents: ['mass_assignment', 'privilege_escalation'],
      requiredRole: 'admin',
      resourceTenant: 'globex',
      expectControlDenied: true,
      proofPatterns: ['SECRET_CANARY_PATTERN'],
      injectedAtMs: 1_700_000_000_000,
      conservedBalance: { balanceField: 'balance', capField: 'limit', unitDebit: 500 },
    }),
    futureWorkerScalar: 'must-not-survive',
  }

  const sanitized = sanitizeSingleHopReceiptForHostCustody(workerPolluted, log, {
    strictHostDerivation: false, // even false must NEVER weaken allowlist custody
  })
  const sanitizedRecord = sanitized as unknown as Record<string, unknown>
  assert.deepEqual(sanitized.exchangeIds, ['ex-1', 'ex-2'], 'host monotonic seq order must override worker array order')
  for (const scalar of [...WORKER_STRIPPED_RECEIPT_SCALARS, 'oracleEvents', 'futureWorkerScalar']) {
    assert.equal(scalar in sanitizedRecord, false, `worker scalar "${scalar}" must NOT survive custody allowlist`)
    assert.equal(sanitizedRecord[scalar], undefined)
  }

  // Only explicitly host-trusted policy.trustedOracleEvents may enter
  const withTrusted = sanitizeSingleHopReceiptForHostCustody(workerPolluted, log, {
    trustedOracleEvents: ['csrf_state_change'],
  })
  assert.deepEqual(withTrusted.oracleEvents, ['csrf_state_change'])

  // HostEvidence seal rejects untrusted plain-object casts at runtime
  const evidence = constructHostEvidence({
    receipt: sanitized,
    transcript: log.toReceiptTranscript(),
    hostOrderedExchangeIds: sanitized.exchangeIds,
    runId: 'run-custody-2',
  })
  assert.equal(isHostEvidence(evidence), true)
  const evidenceReceiptRecord = evidence.receipt as unknown as Record<string, unknown>
  for (const scalar of WORKER_STRIPPED_RECEIPT_SCALARS) {
    assert.equal(scalar in evidenceReceiptRecord, false, `HostEvidence.receipt must omit "${scalar}"`)
  }
  const forgedPlainObject = {
    receipt: sanitized,
    entries: log.toReceiptTranscript().entries ?? [],
    oobEvents: [],
    browserTraces: [],
  }
  assert.equal(isHostEvidence(forgedPlainObject), false)
  assert.throws(
    () => verifyHostEvidence(forgedPlainObject as unknown as HostEvidence),
    /sealed HostEvidence/i,
    'verifyHostEvidence must reject forged non-host casts',
  )
})

// ============================================================================
// Test 3: Per-Run HMAC Cross-Binding Guard & Secret Key Isolation
// ============================================================================

test('R3-16 Test 3: HMAC-bound stamps reject cross-run, cross-oracle, cross-exchange, cross-origin, and tampered citations, and never leak HMAC key', () => {
  const ledger = new NonceLedger()
  const stamp = ledger.mintStamp(
    {
      runId: 'run-A',
      oracleId: 'timing',
      armRole: 'probe',
      origin: ORIGIN,
      method: 'GET',
      route: '/api/report',
      param: 'q',
      exchangeId: 'E1',
    },
    { family: 'timing', delayMs: 2_000 },
  )

  // Exact match succeeds
  assert.ok(ledger.verifyStamp(stamp, {
    runId: 'run-A',
    oracleId: 'timing',
    armRole: 'probe',
    origin: ORIGIN,
    method: 'GET',
    route: '/api/report',
    param: 'q',
    exchangeId: 'E1',
  }))

  // Cross-run rejected
  assert.equal(ledger.verifyStamp(stamp, {
    runId: 'run-B', oracleId: 'timing', armRole: 'probe', origin: ORIGIN, method: 'GET', route: '/api/report', param: 'q', exchangeId: 'E1',
  }), null, 'cross-run citation must be rejected')

  // Omitting runId (downgrade to default run) rejected
  assert.equal(ledger.verifyStamp(stamp, {
    oracleId: 'timing', armRole: 'probe', origin: ORIGIN, method: 'GET', route: '/api/report', param: 'q', exchangeId: 'E1',
  }), null, 'omitted runId on run-scoped stamp must be rejected')

  // Cross-oracle rejected
  assert.equal(ledger.verifyStamp(stamp, {
    runId: 'run-A', oracleId: 'redirect', armRole: 'probe', origin: ORIGIN, method: 'GET', route: '/api/report', param: 'q', exchangeId: 'E1',
  }), null, 'cross-oracle citation must be rejected')

  // Cross-exchange rejected
  assert.equal(ledger.verifyStamp(stamp, {
    runId: 'run-A', oracleId: 'timing', armRole: 'probe', origin: ORIGIN, method: 'GET', route: '/api/report', param: 'q', exchangeId: 'E2',
  }), null, 'cross-exchange citation must be rejected')

  // Cross-origin rejected
  assert.equal(ledger.verifyStamp(stamp, {
    runId: 'run-A', oracleId: 'timing', armRole: 'probe', origin: OTHER_ORIGIN, method: 'GET', route: '/api/report', param: 'q', exchangeId: 'E1',
  }), null, 'cross-origin citation must be rejected')

  // Cross-arm, cross-method, cross-route, cross-param rejected
  assert.equal(ledger.verifyStamp(stamp, {
    runId: 'run-A', oracleId: 'timing', armRole: 'control', origin: ORIGIN, method: 'GET', route: '/api/report', param: 'q', exchangeId: 'E1',
  }), null, 'cross-arm citation must be rejected')
  assert.equal(ledger.verifyStamp(stamp, {
    runId: 'run-A', oracleId: 'timing', armRole: 'probe', origin: ORIGIN, method: 'POST', route: '/api/report', param: 'q', exchangeId: 'E1',
  }), null, 'cross-method citation must be rejected')
  assert.equal(ledger.verifyStamp(stamp, {
    runId: 'run-A', oracleId: 'timing', armRole: 'probe', origin: ORIGIN, method: 'GET', route: '/api/other', param: 'q', exchangeId: 'E1',
  }), null, 'cross-route citation must be rejected')
  assert.equal(ledger.verifyStamp(stamp, {
    runId: 'run-A', oracleId: 'timing', armRole: 'probe', origin: ORIGIN, method: 'GET', route: '/api/report', param: 'other', exchangeId: 'E1',
  }), null, 'cross-param citation must be rejected')

  // Tampered MAC rejected
  const tamperedMac = { ...stamp, mac: `${stamp.mac.slice(0, -1)}${stamp.mac.endsWith('0') ? '1' : '0'}` }
  assert.equal(ledger.verifyStamp(tamperedMac, {
    runId: 'run-A', oracleId: 'timing', armRole: 'probe', origin: ORIGIN, method: 'GET', route: '/api/report', param: 'q', exchangeId: 'E1',
  }), null, 'tampered MAC must be rejected')

  // HMAC key never serialized into worker-facing stamp/challenge metadata
  const serializedStamp = JSON.stringify(stamp)
  assert.equal(serializedStamp.includes('keyHex'), false)
  assert.equal(serializedStamp.includes('secret'), false)
  assert.equal(Object.keys(ledger).length, 0, 'private #runKeys must never be enumerable on NonceLedger')

  // Non-nonce binding kinds preserved for authz/economic/OOB/crypto oracles
  assert.equal(NON_NONCE_ORACLE_BINDING_KINDS.has('persona_tenant'), true)
  assert.equal(NON_NONCE_ORACLE_BINDING_KINDS.has('state_ledger'), true)
  assert.equal(NON_NONCE_ORACLE_BINDING_KINDS.has('crypto_signature'), true)
  assert.equal(NON_NONCE_ORACLE_BINDING_KINDS.has('canary'), true)

  // registerRunDisposer cleans up per-run in-memory state
  assert.equal(ledger.inMemoryStampCount('run-A'), 1)
  runAllRunDisposers('run-A')
  assert.equal(ledger.inMemoryStampCount('run-A'), 0)
  assert.equal(ledger.verifyStamp(stamp, {
    runId: 'run-A', oracleId: 'timing', armRole: 'probe', origin: ORIGIN, method: 'GET', route: '/api/report', param: 'q', exchangeId: 'E1',
  }), null, 'disposed run stamps must no longer verify in memory')
})

// ============================================================================
// Test 4: Restart Persistence (Cited-Only; Zero Hot-Path DB Bloat)
// ============================================================================

test('R3-16 Test 4: cited stamps persist and re-verify after simulated restart while uncited hot-path probes stay off DB', () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'kovo-r3-16-restart-'))
  try {
    const store = new Store(tmpDir)
    const runId = 'run-restart-1'
    const oracle1 = new HostMintedOracle(new NonceLedger({ persistence: store.nonceLedgerPersistence }))

    // Hot probe path: mint 20 uncited probes -> ZERO rows written to SQLite!
    const uncitedTiming = oracle1.mintTimingChallenge('timing', 2_000, undefined, {
      runId, origin: ORIGIN, method: 'GET', route: '/api/slow', param: 'mode',
    })
    for (let i = 0; i < 19; i += 1) {
      oracle1.mintRedirectCanary('canary.kovo.invalid', { runId, origin: ORIGIN, route: `/r/${i}` })
    }
    const countRows = (db: DatabaseSync, table: string): number => {
      const exists = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table)
      if (!exists) return 0
      return Number((db.prepare(`SELECT COUNT(*) AS c FROM ${table}`).get() as { c: number }).c)
    }
    assert.equal(countRows(store.client, 'nonce_ledger_stamps'), 0, 'uncited hot-path probes must not write to nonce_ledger_stamps')
    assert.equal(countRows(store.client, 'nonce_ledger_run_keys'), 0, 'uncited hot-path probes must not write to nonce_ledger_run_keys')

    // Mint & cite 1 timing challenge and 1 redirect canary
    const citedTiming = oracle1.mintTimingChallenge('timing', 2_000, undefined, {
      runId, origin: ORIGIN, method: 'GET', route: '/api/report', param: 'mode',
    })
    const citedRedir = oracle1.mintRedirectCanary('canary.kovo.invalid', {
      runId, origin: ORIGIN, method: 'GET', route: '/auth/continue', param: 'next', armRole: 'probe', exchangeId: 'r-prb',
    })
    assert.equal(oracle1.citeChallenge(citedTiming.challengeId), true)
    assert.equal(oracle1.citeChallenge(citedRedir.canaryId), true)

    assert.equal(countRows(store.client, 'nonce_ledger_stamps'), 2, 'only cited stamps should be persisted')
    assert.equal(countRows(store.client, 'nonce_ledger_run_keys'), 1, 'run key written once on first citation')

    // Simulate process restart: fresh in-memory NonceLedger + HostMintedOracle backed by reopened SQLite DB
    store.close()
    const reopened = new Store(tmpDir)
    try {
      const restartedOracle = new HostMintedOracle(new NonceLedger({ persistence: reopened.nonceLedgerPersistence }))
      assert.equal(restartedOracle.ledger.inMemoryStampCount(), 0)

      // Uncited hot-path probe is NOT in DB -> rejected after restart
      assert.equal(
        restartedOracle.verifyTimingChallenge(uncitedTiming, { runId, origin: ORIGIN, method: 'GET', route: '/api/slow', param: 'mode' }),
        null,
        'uncited probe must fail closed after restart',
      )

      // Cited timing receipt re-verifies cleanly after restart!
      const timingEntries: ReceiptTranscriptEntry[] = Array.from({ length: 5 }, (_, i) => [
        {
          exchangeId: `rc${i}`, seq: i * 2 + 1, origin: ORIGIN, durationMs: 25,
          hostTimingChallenge: citedTiming,
          step: mkStep({ id: `rc${i}`, arm: 'control', method: 'GET', route: '/api/report', pathAndQuery: `/api/report?mode=${encodeURIComponent(citedTiming.controlToken)}`, status: 200 }),
        },
        {
          exchangeId: `rp${i}`, seq: i * 2 + 2, origin: ORIGIN, durationMs: 2_100,
          hostTimingChallenge: citedTiming,
          step: mkStep({ id: `rp${i}`, arm: 'probe', method: 'GET', route: '/api/report', pathAndQuery: `/api/report?mode=${encodeURIComponent(citedTiming.delayToken)}`, status: 200 }),
        },
      ]).flat()
      const timingReceipt = buildProofReceipt({
        vulnClass: 'timing',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/report', param: 'mode' },
        exchangeIds: timingEntries.map(e => e.exchangeId),
        claimedDelta: 'Post-restart retest of cited timing stamp.',
      })
      const timingRes = verifyReceipt(timingReceipt, { entries: timingEntries, runId }, { hostMintedOracle: restartedOracle, runId })
      assert.equal(timingRes.confirmed, true, `restarted timing retest should pass: ${timingRes.reason}`)

      // Cited redirect receipt re-verifies cleanly after restart (and fails on wrong runId)!
      const redirReceipt = buildProofReceipt({
        vulnClass: 'open_redirect',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/auth/continue?next=https://${citedRedir.host}/go`, param: 'next' },
        exchangeIds: ['r-ctl', 'r-prb'],
        claimedDelta: 'Post-restart retest of cited redirect canary.',
      })
      const redirEntries: ReceiptTranscriptEntry[] = [
        { exchangeId: 'r-ctl', origin: ORIGIN, step: mkStep({ id: 'r-ctl', arm: 'control', method: 'GET', route: '/auth/continue', pathAndQuery: '/auth/continue?next=/home', status: 302, responseHeaders: { location: '/home' } }) },
        { exchangeId: 'r-prb', origin: ORIGIN, hostRedirectCanaryHost: citedRedir.host, hostRedirectCanary: citedRedir, step: mkStep({ id: 'r-prb', arm: 'probe', method: 'GET', route: '/auth/continue', pathAndQuery: `/auth/continue?next=${encodeURIComponent(`https://${citedRedir.host}/go`)}`, status: 302, responseHeaders: { location: `https://${citedRedir.host}/go` } }) },
      ]
      const redirOk = verifyReceipt(redirReceipt, { entries: redirEntries, runId }, { hostMintedOracle: restartedOracle, runId })
      assert.equal(redirOk.confirmed, true, `restarted redirect retest should pass: ${redirOk.reason}`)
      const redirWrongRun = verifyReceipt(redirReceipt, { entries: redirEntries, runId: 'run-other' }, { hostMintedOracle: restartedOracle, runId: 'run-other' })
      assert.equal(redirWrongRun.confirmed, false, 'cited redirect stamp must reject cross-run retest')
    } finally {
      reopened.close()
    }
  } finally {
    rmSync(tmpDir, { recursive: true, force: true })
  }
})

// ============================================================================
// Test 5: Deleted Transcript/Any-Arm/Any-Host Fallbacks & Arm Provenance
// ============================================================================

test('R3-16 Test 5: timing rejects transcript-only/partial-arm challenges; redirect rejects unassociated minted hosts; host-assigned arm provenance recorded', async () => {
  const oracle = new HostMintedOracle()
  const runId = 'run-no-fallback'
  const timingChallenge = oracle.mintTimingChallenge('timing', 2_000, undefined, {
    runId, origin: ORIGIN, method: 'GET', route: '/api/report', param: 'mode',
  })

  const makeTimingEntries = (stampControl: boolean, stampProbe: boolean): ReceiptTranscriptEntry[] =>
    Array.from({ length: 5 }, (_, i) => [
      {
        exchangeId: `tc${i}`, seq: i * 2 + 1, origin: ORIGIN, durationMs: 20,
        ...(stampControl ? { hostTimingChallenge: timingChallenge } : {}),
        step: mkStep({ id: `tc${i}`, arm: 'control', method: 'GET', route: '/api/report', pathAndQuery: `/api/report?mode=${encodeURIComponent(timingChallenge.controlToken)}`, status: 200 }),
      },
      {
        exchangeId: `tp${i}`, seq: i * 2 + 2, origin: ORIGIN, durationMs: 2_100,
        ...(stampProbe ? { hostTimingChallenge: timingChallenge } : {}),
        step: mkStep({ id: `tp${i}`, arm: 'probe', method: 'GET', route: '/api/report', pathAndQuery: `/api/report?mode=${encodeURIComponent(timingChallenge.delayToken)}`, status: 200 }),
      },
    ]).flat()

  const timingReceipt = buildProofReceipt({
    vulnClass: 'timing',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/report', param: 'mode' },
    exchangeIds: ['tc0', 'tp0', 'tc1', 'tp1', 'tc2', 'tp2', 'tc3', 'tp3', 'tc4', 'tp4'],
    claimedDelta: 'Timing fallback guard check.',
  })

  // (a) Transcript-level timing challenge with unstamped entries -> REJECTED
  const transcriptOnlyTiming = verifyReceipt(timingReceipt, {
    runId, hostTimingChallenge: timingChallenge, entries: makeTimingEntries(false, false),
  }, { hostMintedOracle: oracle, runId })
  assert.equal(transcriptOnlyTiming.confirmed, false, 'transcript-only timing challenge must be rejected')

  // (b) Probe-only stamped (control unstamped) -> REJECTED (no any-arm fallback)
  const partialArmTiming = verifyReceipt(timingReceipt, {
    runId, entries: makeTimingEntries(false, true),
  }, { hostMintedOracle: oracle, runId })
  assert.equal(partialArmTiming.confirmed, false, 'partial-arm timing challenge must be rejected')

  // (c) All control & probe arms stamped -> CONFIRMED
  const fullBoundTiming = verifyReceipt(timingReceipt, {
    runId, entries: makeTimingEntries(true, true),
  }, { hostMintedOracle: oracle, runId })
  assert.equal(fullBoundTiming.confirmed, true, fullBoundTiming.reason)

  // (d) Redirect: transcript-only OR unassociated minted host -> REJECTED
  const redirCanary = oracle.mintRedirectCanary('canary.kovo.invalid', { runId, origin: ORIGIN, method: 'GET', route: '/go', param: 'next' })
  const otherCanary = oracle.mintRedirectCanary('canary.kovo.invalid', { runId, origin: ORIGIN, method: 'GET', route: '/other', param: 'next' })
  const redirReceipt = buildProofReceipt({
    vulnClass: 'open_redirect',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/go?next=https://${redirCanary.host}/x`, param: 'next' },
    exchangeIds: ['rc', 'rp'],
    claimedDelta: 'Redirect fallback guard check.',
  })
  const ctlEntry: ReceiptTranscriptEntry = {
    exchangeId: 'rc', origin: ORIGIN,
    step: mkStep({ id: 'rc', arm: 'control', method: 'GET', route: '/go', pathAndQuery: '/go?next=/home', status: 302, responseHeaders: { location: '/home' } }),
  }
  const unstampedProbe: ReceiptTranscriptEntry = {
    exchangeId: 'rp', origin: ORIGIN,
    step: mkStep({ id: 'rp', arm: 'probe', method: 'GET', route: '/go', pathAndQuery: `/go?next=${encodeURIComponent(`https://${redirCanary.host}/x`)}`, status: 302, responseHeaders: { location: `https://${redirCanary.host}/x` } }),
  }

  assert.equal(
    verifyReceipt(redirReceipt, { runId, hostRedirectCanaryHost: redirCanary.host, entries: [ctlEntry, unstampedProbe] }, { hostMintedOracle: oracle, runId }).confirmed,
    false,
    'transcript-level hostRedirectCanaryHost fallback must be rejected',
  )
  assert.equal(
    verifyReceipt(redirReceipt, { runId, entries: [ctlEntry, { ...unstampedProbe, hostRedirectCanaryHost: otherCanary.host }] }, { hostMintedOracle: oracle, runId }).confirmed,
    false,
    'mismatched / unassociated minted redirect host must be rejected',
  )
  assert.equal(
    verifyReceipt(redirReceipt, { runId, entries: [ctlEntry, { ...unstampedProbe, hostRedirectCanaryHost: redirCanary.host }] }, { hostMintedOracle: oracle, runId }).confirmed,
    true,
    'probe-bound redirect canary host must confirm',
  )

  // (e) Arm provenance tracking in HostFactLog and verify-prove-handlers
  assert.deepEqual(resolveCanonicalArmWithProvenance('control'), { arm: 'control', provenance: 'worker_selected' })
  assert.deepEqual(resolveCanonicalArmWithProvenance(null, 'probe'), { arm: 'probe', provenance: 'host_assigned' })
  assert.deepEqual(resolveCanonicalArmWithProvenance('probe', 'control', 'host_assigned'), { arm: 'control', provenance: 'host_assigned' })

  const factLog = new HostFactLog()
  const hostFact = factLog.recordExchange({ seq: 1, exchangeId: 'f1', method: 'GET', origin: ORIGIN, pathAndQuery: '/a', status: 200, arm: 'control', armProvenance: 'host_assigned' })
  const workerFact = factLog.recordExchange({ seq: 2, exchangeId: 'f2', method: 'GET', origin: ORIGIN, pathAndQuery: '/a', status: 200, sessionRole: 'probe' })
  assert.equal(hostFact.armProvenance, 'host_assigned')
  assert.equal(workerFact.armProvenance, 'worker_selected')
  assert.equal(factLog.toReceiptTranscript().entries?.[0]?.armProvenance, 'host_assigned')
  assert.equal(factLog.toReceiptTranscript().entries?.[1]?.armProvenance, 'worker_selected')

  // Verify prove.* handlers pass host_assigned armProvenance and runId-bound stamps
  const seenStamps: Array<ProveHttpExchangeStamps | undefined> = []
  const transcript = new TranscriptStore()
  let seq = 0
  const mockHost: ProveHandlerHost = {
    runId: 'run-prove-arm-1',
    transcript,
    defaultOrigin: ORIGIN,
    canaryBroker: undefined,
    scrubRecord: v => v,
    async runOob() { return {} },
    async runRace() { return {} },
    async runHttpExchange(args, _nonce, stamps) {
      seenStamps.push(stamps)
      seq += 1
      const pathAndQuery = String(args.path ?? '/')
      const rec = transcript.record({
        op: 'http', startedAt: 1_000 + seq * 10, durationMs: 25,
        request: { origin: ORIGIN, method: String(args.method ?? 'GET'), pathAndQuery, headers: {}, bodyBytes: 0, bodySha256: 'abc', nonce: 'n', sessionRole: String(args.sessionGroupRole ?? 'probe') },
        body: '{"ok":true}',
        response: { status: 200, headers: { 'content-type': 'application/json' }, bodyBytes: 11, bodySha256: 'abc', mediaType: 'application/json', redirectOrigins: [] },
        ...(stamps?.hostExpressionChallenge ? { hostExpressionChallenge: stamps.hostExpressionChallenge } : {}),
        ...(stamps?.hostBooleanPair ? { hostBooleanPair: stamps.hostBooleanPair } : {}),
      })
      return { exchangeId: rec.exchangeId, status: 200, method: String(args.method ?? 'GET'), pathAndQuery, headers: {}, body: '{"ok":true}', bodyPreview: '{"ok":true}', bodyBytes: 11, bodySha256: 'abc', durationMs: 25, personaHandle: null }
    },
  }
  await handleProveAccessBoundary(mockHost, { route: '/api/admin' }, 'n1')
  assert.equal(seenStamps[0]?.armProvenance, 'host_assigned')
  assert.equal(seenStamps[0]?.hostAssignedArm, 'control')
  assert.equal(seenStamps[1]?.armProvenance, 'host_assigned')
  assert.equal(seenStamps[1]?.hostAssignedArm, 'probe')

  seenStamps.length = 0
  await handleProveDifferential(mockHost, {
    mode: 'timing', timingFamily: 'timing', rounds: 5,
    control: '/api/report?mode={{delayToken}}', variant: '/api/report?mode={{delayToken}}',
  }, 'n2')
  assert.ok(seenStamps.length === 10)
  for (const st of seenStamps) {
    assert.equal(st?.armProvenance, 'host_assigned')
    assert.equal(st?.timingChallenge?.nonceStamp?.runId, 'run-prove-arm-1')
  }

  seenStamps.length = 0
  await handleProveInjection(mockHost, {
    expressionFamily: 'expression',
    control: '/api/calc?expr=1',
    probe: '/api/calc?expr={{expr}}',
  }, 'n3')
  const exprStamps = seenStamps.filter(s => s?.hostExpressionChallenge)
  assert.equal(exprStamps.length, 2)
  for (const st of exprStamps) {
    assert.equal(st?.armProvenance, 'host_assigned')
    assert.equal(st?.hostExpressionChallenge?.nonceStamp?.runId, 'run-prove-arm-1')
  }
})
