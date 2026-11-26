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
import { cut3FloorRecipe, runCut3Recipe } from '../src/server/floor-recipes.ts'
import {
  buildProofReceipt,
  defaultHostMintedOracle,
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

  // Omitting/blank runId is rejected fail-closed (zero wildcard / default-run fallback)
  assert.equal(ledger.verifyStamp(stamp, {
    runId: '', oracleId: 'timing', armRole: 'probe', origin: ORIGIN, method: 'GET', route: '/api/report', param: 'q', exchangeId: 'E1',
  }), null, 'empty runId on run-scoped stamp must be rejected')
  assert.throws(() => ledger.mintStamp({ runId: '', oracleId: 'timing' }, { delayMs: 2_000 }), /runId/i)

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

    // Mint & cite per-exchange bound timing arm stamps and 1 redirect canary
    const citedTimingBase = oracle1.mintTimingChallenge('timing', 2_000, undefined, {
      runId, origin: ORIGIN, method: 'GET', route: '/api/report', param: 'mode',
    })
    const citedTimingEntries: ReceiptTranscriptEntry[] = Array.from({ length: 5 }, (_, i) => {
      const ctlCh = oracle1.stampTimingChallengeArm(citedTimingBase, 'control', { exchangeId: `rc${i}` })
      const prbCh = oracle1.stampTimingChallengeArm(citedTimingBase, 'probe', { exchangeId: `rp${i}` })
      assert.equal(oracle1.citeChallenge(ctlCh.nonceStamp!), true)
      assert.equal(oracle1.citeChallenge(prbCh.nonceStamp!), true)
      return [
        {
          exchangeId: `rc${i}`, seq: i * 2 + 1, origin: ORIGIN, durationMs: 25,
          hostTimingChallenge: ctlCh,
          step: mkStep({ id: `rc${i}`, arm: 'control', method: 'GET', route: '/api/report', pathAndQuery: `/api/report?mode=${encodeURIComponent(citedTimingBase.controlToken)}`, status: 200 }),
        },
        {
          exchangeId: `rp${i}`, seq: i * 2 + 2, origin: ORIGIN, durationMs: 2_100,
          hostTimingChallenge: prbCh,
          step: mkStep({ id: `rp${i}`, arm: 'probe', method: 'GET', route: '/api/report', pathAndQuery: `/api/report?mode=${encodeURIComponent(citedTimingBase.delayToken)}`, status: 200 }),
        },
      ]
    }).flat()
    const citedRedir = oracle1.mintRedirectCanary('canary.kovo.invalid', {
      runId, origin: ORIGIN, method: 'GET', route: '/auth/continue', param: 'next', armRole: 'probe', exchangeId: 'r-prb',
    })
    assert.equal(oracle1.citeChallenge(citedRedir.canaryId), true)

    assert.equal(countRows(store.client, 'nonce_ledger_stamps'), 11, 'only cited stamps (10 timing arms + 1 redirect) should be persisted')
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
      const timingReceipt = buildProofReceipt({
        vulnClass: 'timing',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/report', param: 'mode' },
        exchangeIds: citedTimingEntries.map(e => e.exchangeId),
        claimedDelta: 'Post-restart retest of cited timing stamp.',
      })
      const timingRes = verifyReceipt(timingReceipt, { entries: citedTimingEntries, runId }, { hostMintedOracle: restartedOracle, runId })
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

  const makeTimingEntries = (stampControl: boolean, stampProbe: boolean, bindArmExchange = true): ReceiptTranscriptEntry[] =>
    Array.from({ length: 5 }, (_, i) => [
      {
        exchangeId: `tc${i}`, seq: i * 2 + 1, origin: ORIGIN, durationMs: 20,
        ...(stampControl ? { hostTimingChallenge: bindArmExchange ? oracle.stampTimingChallengeArm(timingChallenge, 'control', { exchangeId: `tc${i}` }) : timingChallenge } : {}),
        step: mkStep({ id: `tc${i}`, arm: 'control', method: 'GET', route: '/api/report', pathAndQuery: `/api/report?mode=${encodeURIComponent(timingChallenge.controlToken)}`, status: 200 }),
      },
      {
        exchangeId: `tp${i}`, seq: i * 2 + 2, origin: ORIGIN, durationMs: 2_100,
        ...(stampProbe ? { hostTimingChallenge: bindArmExchange ? oracle.stampTimingChallengeArm(timingChallenge, 'probe', { exchangeId: `tp${i}` }) : timingChallenge } : {}),
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

  // (b2) B1: Unbound run-scoped timing stamp (armRole/exchangeId = null) -> REJECTED (zero wildcard!)
  const unboundTiming = verifyReceipt(timingReceipt, {
    runId, entries: makeTimingEntries(true, true, false),
  }, { hostMintedOracle: oracle, runId })
  assert.equal(unboundTiming.confirmed, false, 'unbound run-scoped timing stamp (null armRole/exchangeId) must be rejected')

  // (c) All control & probe arms stamped with per-arm/per-exchange bindings -> CONFIRMED
  const fullBoundTiming = verifyReceipt(timingReceipt, {
    runId, entries: makeTimingEntries(true, true, true),
  }, { hostMintedOracle: oracle, runId })
  assert.equal(fullBoundTiming.confirmed, true, fullBoundTiming.reason)

  // (d) Redirect: transcript-only, unbound, OR unassociated minted host -> REJECTED
  const unboundRedirCanary = oracle.mintRedirectCanary('canary.kovo.invalid', { runId, origin: ORIGIN, method: 'GET', route: '/go', param: 'next' })
  const redirCanary = oracle.mintRedirectCanary('canary.kovo.invalid', { runId, origin: ORIGIN, method: 'GET', route: '/go', param: 'next', armRole: 'probe', exchangeId: 'rp' })
  const otherCanary = oracle.mintRedirectCanary('canary.kovo.invalid', { runId, origin: ORIGIN, method: 'GET', route: '/other', param: 'next', armRole: 'probe', exchangeId: 'rp' })
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
  const unboundRedirReceipt = buildProofReceipt({
    vulnClass: 'open_redirect',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/go?next=https://${unboundRedirCanary.host}/x`, param: 'next' },
    exchangeIds: ['rc', 'rp'],
    claimedDelta: 'Unbound redirect guard check.',
  })
  assert.equal(
    verifyReceipt(unboundRedirReceipt, {
      runId,
      entries: [ctlEntry, {
        ...unstampedProbe,
        hostRedirectCanaryHost: unboundRedirCanary.host,
        step: mkStep({ id: 'rp', arm: 'probe', method: 'GET', route: '/go', pathAndQuery: `/go?next=${encodeURIComponent(`https://${unboundRedirCanary.host}/x`)}`, status: 302, responseHeaders: { location: `https://${unboundRedirCanary.host}/x` } }),
      }],
    }, { hostMintedOracle: oracle, runId }).confirmed,
    false,
    'B1: unbound run-scoped redirect canary (null armRole/exchangeId) must be rejected',
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

  // (e) Arm provenance tracking in HostFactLog and verify-prove-handlers (N1: absent sessionRole -> worker_selected)
  assert.deepEqual(resolveCanonicalArmWithProvenance('control'), { arm: 'control', provenance: 'worker_selected' })
  assert.deepEqual(resolveCanonicalArmWithProvenance(null), { arm: 'probe', provenance: 'worker_selected' })
  assert.deepEqual(resolveCanonicalArmWithProvenance(undefined), { arm: 'probe', provenance: 'worker_selected' })
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
    control: '/api/Report?mode={{delayToken}}', variant: '/api/Report?mode={{delayToken}}',
  }, 'n2')
  assert.ok(seenStamps.length === 10)
  const ctlTimingStamps = seenStamps.filter(s => s?.hostAssignedArm === 'control')
  const prbTimingStamps = seenStamps.filter(s => s?.hostAssignedArm === 'probe')
  assert.equal(ctlTimingStamps.length, 5)
  assert.equal(prbTimingStamps.length, 5)
  for (const st of seenStamps) {
    const ns = st?.timingChallenge?.nonceStamp
    assert.equal(st?.armProvenance, 'host_assigned')
    assert.equal(ns?.runId, 'run-prove-arm-1')
    assert.equal(ns?.origin, ORIGIN)
    assert.equal(ns?.method, 'GET')
    assert.equal(ns?.route, '/api/Report')
    assert.equal(ns?.param, 'mode')
    assert.equal(ns?.armRole, st?.hostAssignedArm)
  }
  assert.notEqual(
    ctlTimingStamps[0]?.timingChallenge?.nonceStamp?.stampId,
    prbTimingStamps[0]?.timingChallenge?.nonceStamp?.stampId,
    'control and probe timing arms must carry distinct per-arm HMAC stamps',
  )

  seenStamps.length = 0
  await handleProveInjection(mockHost, {
    expressionFamily: 'expression',
    control: '/api/Calc?expr=1',
    probe: '/api/Calc?expr={{expr}}',
  }, 'n3')
  const exprStamps = seenStamps.filter(s => s?.hostExpressionChallenge)
  assert.equal(exprStamps.length, 2)
  for (const st of exprStamps) {
    const ns = st?.hostExpressionChallenge?.nonceStamp
    assert.equal(st?.armProvenance, 'host_assigned')
    assert.equal(ns?.runId, 'run-prove-arm-1')
    assert.equal(ns?.origin, ORIGIN)
    assert.equal(ns?.method, 'GET')
    assert.equal(ns?.route, '/api/Calc')
    assert.equal(ns?.param, 'expr')
    assert.equal(ns?.armRole, 'probe')
  }
})

// ============================================================================
// Test 6: B1 Zero-Wildcard Verification & N5 Case-Preserving Route Binding
// ============================================================================

test('R3-16 Test 6 (B1/N5): unbound null-field stamps fail closed and route binding is case-sensitive', () => {
  const ledger = new NonceLedger()
  const runId = 'run-b1-strict'

  // Unbound stamp (origin/method/route/param/armRole/exchangeId all null) must NEVER match expected dimensions
  const unbound = ledger.mintStamp({ runId, oracleId: 'timing' }, { delayMs: 2_000 })
  assert.equal(ledger.verifyStamp(unbound, { runId, oracleId: 'timing', origin: ORIGIN }), null, 'null origin must fail closed')
  assert.equal(ledger.verifyStamp(unbound, { runId, oracleId: 'timing', method: 'GET' }), null, 'null method must fail closed')
  assert.equal(ledger.verifyStamp(unbound, { runId, oracleId: 'timing', route: '/api/R1' }), null, 'null route must fail closed')
  assert.equal(ledger.verifyStamp(unbound, { runId, oracleId: 'timing', param: 'q' }), null, 'null param must fail closed')
  assert.equal(ledger.verifyStamp(unbound, { runId, oracleId: 'timing', armRole: 'probe' }), null, 'null armRole must fail closed')
  assert.equal(ledger.verifyStamp(unbound, { runId, oracleId: 'timing', exchangeId: 'E1' }), null, 'null exchangeId must fail closed')

  // Case-sensitive route binding (N5): /api/Items != /api/items
  const cased = ledger.mintStamp(
    { runId, oracleId: 'redirect', origin: ORIGIN, method: 'GET', route: '/api/Items', param: 'next', armRole: 'probe', exchangeId: 'E1' },
    { host: 'redir-a.canary.kovo.invalid' },
  )
  assert.ok(ledger.verifyStamp(cased, { runId, oracleId: 'redirect', origin: ORIGIN, method: 'GET', route: '/api/Items', param: 'next', armRole: 'probe', exchangeId: 'E1' }))
  assert.equal(ledger.verifyStamp(cased, { runId, oracleId: 'redirect', origin: ORIGIN, method: 'GET', route: '/api/items', param: 'next', armRole: 'probe', exchangeId: 'E1' }), null, 'case-mismatched route must be rejected')
  assert.equal(ledger.verifyStamp(cased, { runId, oracleId: 'redirect', origin: ORIGIN, method: 'GET', route: '/api/Items', param: 'next', armRole: 'probe', exchangeId: 'E2' }), null, 'cross-exchange must be rejected')
  assert.equal(ledger.verifyStamp(cased, { runId, oracleId: 'redirect', origin: ORIGIN, method: 'GET', route: '/api/Items', param: 'next', armRole: 'probe' }), null, 'omitting exchangeId on exchange-bound stamp must be rejected')

  // HostMintedOracle timing & redirect cross-route / cross-exchange / swapped-arm rejection
  const oracle = new HostMintedOracle(ledger)
  const tBase = oracle.mintTimingChallenge('timing', 2_000, undefined, { runId, origin: ORIGIN, method: 'GET', route: '/api/R1', param: 'q' })
  const tProbeE1 = oracle.stampTimingChallengeArm(tBase, 'probe', { exchangeId: 'E1' })
  assert.ok(oracle.verifyTimingChallenge(tProbeE1, { runId, origin: ORIGIN, method: 'GET', route: '/api/R1', param: 'q', armRole: 'probe', exchangeId: 'E1' }))
  assert.equal(oracle.verifyTimingChallenge(tProbeE1, { runId, origin: ORIGIN, method: 'GET', route: '/api/R2', param: 'q', armRole: 'probe', exchangeId: 'E1' }), null, 'cross-route timing rejected')
  assert.equal(oracle.verifyTimingChallenge(tProbeE1, { runId, origin: ORIGIN, method: 'GET', route: '/api/R1', param: 'q', armRole: 'probe', exchangeId: 'E2' }), null, 'cross-exchange timing rejected')
  assert.equal(oracle.verifyTimingChallenge(tProbeE1, { runId, origin: ORIGIN, method: 'GET', route: '/api/R1', param: 'q', armRole: 'control', exchangeId: 'E1' }), null, 'swapped control/probe arm timing rejected')
})

// ============================================================================
// Test 7: B2 Direct verifyReceipt Custody & N2 WeakSet Spread-Clone Rejection
// ============================================================================

test('R3-16 Test 7 (B2/N2): direct verifyReceipt ignores worker scalars/oracleEvents and WeakSet seal rejects spread clones', () => {
  // B2a: Direct verifyReceipt on own-tenant benign note read with ALL worker claim scalars + handle-shaped ID -> REJECTED
  const ownTenantEntries: ReceiptTranscriptEntry[] = [
    {
      exchangeId: 'ctl_notes', origin: ORIGIN,
      step: mkStep({ id: 'ctl_notes', arm: 'control', method: 'GET', route: '/api/v1/notes', pathAndQuery: '/api/v1/notes', status: 200, actor: { handle: 'member_a', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, body: '{"items":[{"id":"usr_note_0a1b2c3d4e5f","tenant_id":"tenant-a","owner":"u-a1"}]}' }),
    },
    {
      exchangeId: 'prb_note', origin: ORIGIN,
      step: mkStep({ id: 'prb_note', arm: 'probe', method: 'GET', route: '/api/v1/notes/usr_note_0a1b2c3d4e5f', pathAndQuery: '/api/v1/notes/usr_note_0a1b2c3d4e5f', status: 200, actor: { handle: 'member_a', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, body: '{"id":"usr_note_0a1b2c3d4e5f","tenant_id":"tenant-a","owner":"u-a1","text":"mine"}' }),
    },
  ]
  const pollutedBola = buildProofReceipt({
    vulnClass: 'bola',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/notes/usr_note_0a1b2c3d4e5f' },
    exchangeIds: ['ctl_notes', 'prb_note'],
    claimedDelta: 'Worker-polluted own-tenant read.',
    requiredRole: 'admin',
    resourceTenant: 'tenant-b',
    expectControlDenied: true,
    oracleEvents: ['privilege_escalation', 'csrf_missing'],
    proofPatterns: ['usr_note_[0-9a-f]{12}'],
  })
  assert.equal(verifyReceipt(pollutedBola, { entries: ownTenantEntries }).confirmed, false, 'direct verifyReceipt must ignore all worker scalars and dismiss own-tenant read')

  // B2b: Direct verifyReceipt with forged oracleEvents=['mass_assignment'] on non-protected self-bio edit -> REJECTED
  const bioEntries: ReceiptTranscriptEntry[] = [
    { exchangeId: 'b1', origin: ORIGIN, step: mkStep({ id: 'b1', arm: 'control', method: 'GET', route: '/api/profile', status: 200, body: '{"bio":"old","role":"member"}' }) },
    { exchangeId: 'b2', origin: ORIGIN, step: mkStep({ id: 'b2', arm: 'probe', method: 'PATCH', route: '/api/profile', status: 200, requestBody: '{"bio":"new"}', body: '{"bio":"new","role":"member"}' }) },
    { exchangeId: 'b3', origin: ORIGIN, step: mkStep({ id: 'b3', arm: 'control', method: 'GET', route: '/api/profile', status: 200, body: '{"bio":"new","role":"member"}' }) },
  ]
  const forgedMass = buildProofReceipt({
    vulnClass: 'mass_assignment',
    target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/api/profile' },
    exchangeIds: ['b1', 'b2', 'b3'],
    claimedDelta: 'Worker forged oracleEvents on benign bio edit.',
    oracleEvents: ['mass_assignment', 'privilege_escalation'],
    requiredRole: 'admin',
  })
  assert.equal(verifyReceipt(forgedMass, { entries: bioEntries }).confirmed, false, 'direct verifyReceipt must strip forged worker oracleEvents')

  // N2: WeakSet seal rejects spread-cloning `{ ...genuine, receipt: forged }`
  const genuine = constructHostEvidence({ receipt: pollutedBola, transcript: { entries: ownTenantEntries }, runId: 'run-n2' })
  assert.equal(isHostEvidence(genuine), true)
  const spreadClone = { ...genuine, receipt: { ...genuine.receipt, vulnClass: 'rce' } }
  assert.equal(isHostEvidence(spreadClone), false, 'spread clone of HostEvidence must NOT pass WeakSet seal')
  assert.throws(() => verifyHostEvidence(spreadClone as unknown as HostEvidence), /sealed HostEvidence/i)
})

// ============================================================================
// Test 8: B3 Payload-Digest Mix-and-Match & SQLite DB-Tamper Fail-Closed
// ============================================================================

test('R3-16 Test 8 (B3): challenge/stamp mix-and-match and tampered SQLite payload_json fail closed', () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'kovo-r3-16-b3-'))
  try {
    const store = new Store(tmpDir)
    const runId = 'run-b3-integrity'
    const oracle1 = new HostMintedOracle(new NonceLedger({ persistence: store.nonceLedgerPersistence }))

    // 1. Mix-and-match: Challenge A's payload paired with Challenge B's valid same-oracle nonceStamp -> REJECTED
    const exprA = oracle1.mintExpressionChallenge('ssti', '*', { runId, origin: ORIGIN, method: 'GET', route: '/e', param: 'q', armRole: 'probe' })
    const exprB = oracle1.mintExpressionChallenge('ssti', '*', { runId, origin: ORIGIN, method: 'GET', route: '/e', param: 'q', armRole: 'probe' })
    assert.equal(oracle1.verifyExpressionChallenge({ ...exprA, nonceStamp: exprB.nonceStamp }, { runId, origin: ORIGIN, method: 'GET', route: '/e', param: 'q', armRole: 'probe' }), null, 'expression mix-and-match must fail closed')

    const timeA = oracle1.mintTimingChallenge('timing', 2_000, undefined, { runId, origin: ORIGIN, method: 'GET', route: '/t', param: 'q', armRole: 'probe' })
    const timeB = oracle1.mintTimingChallenge('timing', 3_000, undefined, { runId, origin: ORIGIN, method: 'GET', route: '/t', param: 'q', armRole: 'probe' })
    assert.equal(oracle1.verifyTimingChallenge({ ...timeA, nonceStamp: timeB.nonceStamp }, { runId, origin: ORIGIN, method: 'GET', route: '/t', param: 'q', armRole: 'probe' }), null, 'timing mix-and-match must fail closed')

    const redirA = oracle1.mintRedirectCanary('canary.kovo.invalid', { runId, origin: ORIGIN, method: 'GET', route: '/r', param: 'next', armRole: 'probe' })
    const redirB = oracle1.mintRedirectCanary('canary.kovo.invalid', { runId, origin: ORIGIN, method: 'GET', route: '/r', param: 'next', armRole: 'probe' })
    assert.equal(oracle1.verifyRedirectCanary({ ...redirA, nonceStamp: redirB.nonceStamp }, { runId, origin: ORIGIN, method: 'GET', route: '/r', param: 'next', armRole: 'probe' }), null, 'redirect mix-and-match must fail closed')

    const boolA = oracle1.mintBooleanPair('10', { style: 'numeric', param: 'id', binding: { runId, origin: ORIGIN, method: 'GET', route: '/b' } })
    const boolB = oracle1.mintBooleanPair('20', { style: 'numeric', param: 'id', binding: { runId, origin: ORIGIN, method: 'GET', route: '/b' } })
    const stampedA = oracle1.stampBooleanPairArm(boolA, 'true', { exchangeId: 'eb1' })
    const stampedB = oracle1.stampBooleanPairArm(boolB, 'true', { exchangeId: 'eb1' })
    assert.equal(oracle1.verifyBooleanPair({ ...stampedA, nonceStamp: stampedB.nonceStamp }, { runId, origin: ORIGIN, method: 'GET', route: '/b', param: 'id', armRole: 'true', exchangeId: 'eb1' }), null, 'boolean pair mix-and-match must fail closed')

    // 2. SQLite payload_json tamper test: cite challenges, tamper persisted payload_json, reopen fresh ledger -> FAIL CLOSED
    assert.equal(oracle1.citeChallenge(timeA.challengeId), true)
    assert.equal(oracle1.citeChallenge(exprA.challengeId), true)
    assert.equal(oracle1.citeChallenge(redirA.canaryId), true)

    const tamperedTimePayload = JSON.stringify({ ...timeA, delayMs: 1_000, delayToken: 'delay=0' })
    const tamperedExprPayload = JSON.stringify({ ...exprA, expectedOutput: '00000' })
    const tamperedRedirPayload = JSON.stringify({ ...redirA, host: 'evil.example.invalid' })
    store.client.prepare('UPDATE nonce_ledger_stamps SET payload_json = ? WHERE stamp_id = ?').run(tamperedTimePayload, timeA.challengeId)
    store.client.prepare('UPDATE nonce_ledger_stamps SET payload_json = ? WHERE stamp_id = ?').run(tamperedExprPayload, exprA.challengeId)
    store.client.prepare('UPDATE nonce_ledger_stamps SET payload_json = ? WHERE stamp_id = ?').run(tamperedRedirPayload, redirA.canaryId)
    store.close()

    const reopened = new Store(tmpDir)
    try {
      const restartedLedger = new NonceLedger({ persistence: reopened.nonceLedgerPersistence })
      const restartedOracle = new HostMintedOracle(restartedLedger)
      assert.equal(restartedLedger.getVerifiedPayload(timeA.challengeId, runId), null, 'tampered timing payload_json must fail digest verification')
      assert.equal(restartedLedger.getVerifiedPayload(exprA.challengeId, runId), null, 'tampered expression payload_json must fail digest verification')
      assert.equal(restartedLedger.getVerifiedPayload(redirA.canaryId, runId), null, 'tampered redirect payload_json must fail digest verification')
      assert.equal(restartedOracle.getTimingChallenge(timeA.challengeId, runId), undefined)
      assert.equal(restartedOracle.getExpressionChallenge(exprA.challengeId, runId), undefined)
      assert.equal(restartedOracle.verifyTimingChallenge(timeA, { runId, origin: ORIGIN, method: 'GET', route: '/t', param: 'q', armRole: 'probe' }), null)
      assert.equal(restartedOracle.verifyExpressionChallenge(exprA, { runId, origin: ORIGIN, method: 'GET', route: '/e', param: 'q', armRole: 'probe' }), null)
      assert.equal(restartedOracle.verifyRedirectCanary(redirA, { runId, origin: ORIGIN, method: 'GET', route: '/r', param: 'next', armRole: 'probe' }), null)
    } finally {
      reopened.close()
    }
  } finally {
    rmSync(tmpDir, { recursive: true, force: true })
  }
})

// ============================================================================
// Test 9: B1 End-to-End Handler -> Transcript -> verifyReceipt WITH Real runId
//         (Timing, Boolean, Expression, Redirect TPs + Cross-Exchange/Route/Run/No-RunId Negatives)
//         + N3' Own-API-Key Self-Service FP Guard + bindStamp(payloadJson=null) Preservation
// ============================================================================

test('R3-16 Test 9 (B1 E2E + N3\'): handler->transcript->verifyReceipt with real runId confirms timing/boolean/expression/redirect TPs and rejects E2/R2/runB/no-runId reuse', async () => {
  // Helper: build a ProveHandlerHost wired to a TranscriptStore that records stamps & returns them to HostFactLog
  const makeE2eHost = (
    runId: string,
    responder: (args: Record<string, unknown>) => { status: number; body: string; durationMs?: number; headers?: Record<string, string> },
  ) => {
    const transcript = new TranscriptStore()
    let seq = 0
    const host: ProveHandlerHost = {
      runId,
      transcript,
      defaultOrigin: ORIGIN,
      canaryBroker: undefined,
      scrubRecord: v => v,
      async runOob() { return {} },
      async runRace() { return {} },
      async runHttpExchange(args, nonce, stamps) {
        seq += 1
        const method = String(args.method ?? 'GET').toUpperCase()
        const pathAndQuery = String(args.path ?? '/')
        const res = responder(args)
        const durationMs = res.durationMs ?? 25
        const rec = transcript.record({
          op: 'http', startedAt: 1_000 + seq * 50, durationMs,
          request: { origin: ORIGIN, method, pathAndQuery, headers: {}, bodyBytes: 0, bodySha256: '0'.repeat(64), nonce, sessionRole: String(args.sessionGroupRole ?? 'probe') },
          body: res.body,
          response: { status: res.status, headers: res.headers ?? { 'content-type': 'application/json' }, bodyBytes: Buffer.byteLength(res.body), bodySha256: '1'.repeat(64), mediaType: 'application/json', redirectOrigins: [] },
          ...(stamps?.hostExpressionChallenge ? { hostExpressionChallenge: stamps.hostExpressionChallenge } : {}),
          ...(stamps?.hostBooleanPair ? { hostBooleanPair: stamps.hostBooleanPair } : {}),
          ...(stamps?.timingChallenge ? { hostTimingStamp: stamps.timingChallenge } : {}),
        })
        return { exchangeId: rec.exchangeId, status: res.status, method, pathAndQuery, headers: res.headers ?? { 'content-type': 'application/json' }, body: res.body, bodyPreview: res.body.slice(0, 120), bodyBytes: Buffer.byteLength(res.body), bodySha256: '1'.repeat(64), durationMs, personaHandle: null }
      },
    }
    const toTranscript = () => {
      const log = HostFactLog.fromTranscriptStore(transcript, { runId })
      return log.toReceiptTranscript()
    }
    return { host, transcript, toTranscript }
  }

  // 1. TIMING E2E: handleProveDifferential(mode:'timing') -> post-send bindStampToExchange -> verifyReceipt
  const timingRunId = 'run-e2e-timing-1'
  const timingHarness = makeE2eHost(timingRunId, (args) => {
    const p = String(args.path ?? '')
    const isDelay = p.includes('delay=2000')
    return { status: 200, body: '{"ok":true}', durationMs: isDelay ? 2_100 : 25 }
  })
  const timingOut = await handleProveDifferential(timingHarness.host, {
    mode: 'timing', timingFamily: 'timing', rounds: 5,
    control: '/api/Report?mode={{delayToken}}', variant: '/api/Report?mode={{delayToken}}',
  }, 'n-e2e-t') as { ok: boolean; controlIds: string[]; variantIds: string[] }
  assert.equal(timingOut.ok, true)
  const timingTx = timingHarness.toTranscript()
  // Verify post-send exchangeId binding was persisted onto every transcript entry!
  for (const e of timingTx.entries!) {
    assert.equal(e.hostTimingChallenge?.nonceStamp?.exchangeId, e.exchangeId, 'timing entry must carry exchangeId-bound child stamp')
    assert.equal(e.hostTimingChallenge?.nonceStamp?.runId, timingRunId)
  }
  const timingIds = timingOut.controlIds.flatMap((cid, i) => [cid, timingOut.variantIds[i]!])
  const timingReceipt = buildProofReceipt({
    vulnClass: 'timing',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/Report', param: 'mode' },
    exchangeIds: timingIds,
    claimedDelta: 'E2E timing confirmation with post-send exchange-bound stamps.',
  })
  const timingTp = verifyReceipt(timingReceipt, timingTx, { runId: timingRunId })
  assert.equal(timingTp.confirmed, true, `Timing E2E TP must confirm: ${timingTp.reason}`)
  // Negatives: cite exact stamp on E2, route R2, run B, or with no runId -> ALL REJECT
  const swappedTimingEntries = timingTx.entries!.map((e, i) => i === 0 ? { ...e, hostTimingChallenge: timingTx.entries![2]!.hostTimingChallenge } : e)
  assert.equal(verifyReceipt(timingReceipt, { ...timingTx, entries: swappedTimingEntries }, { runId: timingRunId }).confirmed, false, 'timing stamp reused on E2 must reject')
  const route2TimingEntries = timingTx.entries!.map(e => ({ ...e, step: { ...e.step, route: '/api/Other', pathAndQuery: e.step.pathAndQuery?.replace('/api/Report', '/api/Other') } }))
  assert.equal(verifyReceipt(buildProofReceipt({ ...timingReceipt, target: { ...timingReceipt.target, pathAndQuery: '/api/Other' } }), { ...timingTx, entries: route2TimingEntries }, { runId: timingRunId }).confirmed, false, 'timing stamp reused on route R2 must reject')
  assert.equal(verifyReceipt(timingReceipt, { ...timingTx, runId: 'run-B' }, { runId: 'run-B' }).confirmed, false, 'timing stamp reused on run B must reject')
  assert.equal(verifyReceipt(timingReceipt, { entries: timingTx.entries }).confirmed, false, 'timing without host runId must reject')

  // 2. BOOLEAN E2E: handleProveDifferential(mode:'boolean') -> post-send bindStampToExchange -> verifyReceipt
  const boolRunId = 'run-e2e-bool-1'
  const boolHarness = makeE2eHost(boolRunId, (args) => {
    const p = decodeURIComponent(String(args.path ?? ''))
    const m = /AND (\d+)=(\d+)/.exec(p)
    const isFalse = Boolean(m && m[1] !== m[2])
    return { status: 200, body: isFalse ? '{"id":null,"rows":0,"status":"empty"}' : '{"id":7,"rows":1,"status":"active"}' }
  })
  const boolOut = await handleProveDifferential(boolHarness.host, {
    mode: 'boolean', booleanBase: '7', booleanStyle: 'numeric', rounds: 2,
    baseline: '/api/Items?id={{boolBase}}', control: '/api/Items?id={{boolTrue}}', variant: '/api/Items?id={{boolFalse}}',
  }, 'n-e2e-b') as { ok: boolean; baselineIds: string[]; controlIds: string[]; variantIds: string[] }
  assert.equal(boolOut.ok, true)
  const boolTx = boolHarness.toTranscript()
  for (const e of boolTx.entries!) {
    assert.equal(e.hostBooleanPair?.nonceStamp?.exchangeId, e.exchangeId, 'boolean entry must carry exchangeId-bound child stamp')
    assert.equal(e.hostBooleanPair?.nonceStamp?.runId, boolRunId)
  }
  const boolReceipt = buildProofReceipt({
    vulnClass: 'sqli',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/Items', param: 'id' },
    exchangeIds: [...boolOut.baselineIds, ...boolOut.controlIds, ...boolOut.variantIds],
    claimedDelta: 'E2E boolean confirmation with post-send exchange-bound stamps.',
  })
  const boolTp = verifyReceipt(boolReceipt, boolTx, { runId: boolRunId })
  assert.equal(boolTp.confirmed, true, `Boolean E2E TP must confirm: ${boolTp.reason}`)
  const swappedBoolEntries = boolTx.entries!.map((e, i) => i === 2 ? { ...e, hostBooleanPair: boolTx.entries![5]!.hostBooleanPair } : e)
  assert.equal(verifyReceipt(boolReceipt, { ...boolTx, entries: swappedBoolEntries }, { runId: boolRunId }).confirmed, false, 'boolean stamp reused on E2 must reject')
  const route2BoolEntries = boolTx.entries!.map(e => ({ ...e, step: { ...e.step, route: '/api/Other', pathAndQuery: e.step.pathAndQuery?.replace('/api/Items', '/api/Other') } }))
  assert.equal(verifyReceipt(buildProofReceipt({ ...boolReceipt, target: { ...boolReceipt.target, pathAndQuery: '/api/Other' } }), { ...boolTx, entries: route2BoolEntries }, { runId: boolRunId }).confirmed, false, 'boolean stamp reused on route R2 must reject')
  assert.equal(verifyReceipt(boolReceipt, { ...boolTx, runId: 'run-B' }, { runId: 'run-B' }).confirmed, false, 'boolean stamp reused on run B must reject')
  assert.equal(verifyReceipt(boolReceipt, { entries: boolTx.entries }).confirmed, false, 'boolean without host runId must reject')

  // 3. EXPRESSION E2E: handleProveInjection -> post-send bindStampToExchange -> verifyReceipt
  const exprRunId = 'run-e2e-expr-1'
  const exprHarness = makeE2eHost(exprRunId, (args) => {
    const q = new URL(String(args.path ?? '/'), ORIGIN).searchParams.get('tpl') ?? ''
    const m = /^(\d+)\*(\d+)$/.exec(q)
    return { status: 200, body: m ? `Rendered ${Number(m[1]) * Number(m[2])}` : `Rendered ${q}` }
  })
  const exprOut = await handleProveInjection(exprHarness.host, {
    expressionFamily: 'ssti', control: '/api/Render?tpl=hello', probe: '/api/Render?tpl={{expr}}',
  }, 'n-e2e-e') as { ok: boolean; control: { exchangeId: string }; probe: { exchangeId: string }; probe2: { exchangeId: string }; control2: { exchangeId: string } }
  assert.equal(exprOut.ok, true)
  const exprTx = exprHarness.toTranscript()
  const prbExprEntries = exprTx.entries!.filter(e => e.hostExpressionChallenge)
  assert.equal(prbExprEntries.length, 2)
  for (const e of prbExprEntries) {
    assert.equal(e.hostExpressionChallenge?.nonceStamp?.exchangeId, e.exchangeId, 'expression probe must carry exchangeId-bound child stamp')
    assert.equal(e.hostExpressionChallenge?.nonceStamp?.runId, exprRunId)
  }
  const exprReceipt = buildProofReceipt({
    vulnClass: 'ssti',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/Render', param: 'tpl' },
    exchangeIds: [exprOut.control.exchangeId, exprOut.probe.exchangeId, exprOut.probe2.exchangeId, exprOut.control2.exchangeId],
    claimedDelta: 'E2E expression confirmation with post-send exchange-bound stamps.',
  })
  const exprTp = verifyReceipt(exprReceipt, exprTx, { runId: exprRunId })
  assert.equal(exprTp.confirmed, true, `Expression E2E TP must confirm: ${exprTp.reason}`)
  const swappedExprEntries = exprTx.entries!.map(e => e.exchangeId === exprOut.probe.exchangeId ? { ...e, hostExpressionChallenge: prbExprEntries[1]!.hostExpressionChallenge } : e)
  assert.equal(verifyReceipt(exprReceipt, { ...exprTx, entries: swappedExprEntries }, { runId: exprRunId }).confirmed, false, 'expression stamp reused on E2 must reject')
  const route2ExprEntries = exprTx.entries!.map(e => ({ ...e, step: { ...e.step, route: '/api/Other', pathAndQuery: e.step.pathAndQuery?.replace('/api/Render', '/api/Other') } }))
  assert.equal(verifyReceipt(buildProofReceipt({ ...exprReceipt, target: { ...exprReceipt.target, pathAndQuery: '/api/Other' } }), { ...exprTx, entries: route2ExprEntries }, { runId: exprRunId }).confirmed, false, 'expression stamp reused on route R2 must reject')
  assert.equal(verifyReceipt(exprReceipt, { ...exprTx, runId: 'run-B' }, { runId: 'run-B' }).confirmed, false, 'expression stamp reused on run B must reject')
  assert.equal(verifyReceipt(exprReceipt, { entries: exprTx.entries }).confirmed, false, 'expression without host runId must reject')

  // 4. REDIRECT E2E: cut3FloorRecipe('redirect') -> full tuple mint + post-send per-probe child stamp -> verifyReceipt
  const redirRunId = 'run-e2e-redir-1'
  const redirExec = await runCut3Recipe(cut3FloorRecipe('redirect', {
    origin: ORIGIN,
    method: 'GET',
    pathAndQuery: '/auth/Go?next=https://{{redirectHost}}/cb',
    controlPathAndQuery: '/auth/Go?next=/dashboard',
    probePathAndQuery: '/auth/Go?next=https://{{redirectHost}}/cb',
    vulnClass: 'open_redirect',
    actor: { handle: 'alice', role: 'member', tenant: 'acme', auth: 'cookie' },
  }), {
    runId: redirRunId,
    request(spec) {
      const next = new URL(spec.pathAndQuery, ORIGIN).searchParams.get('next') ?? '/home'
      return { status: 302, responseHeaders: { location: next }, body: '' }
    },
  })
  assert.equal(redirExec.result.confirmed, true, `Redirect E2E TP must confirm: ${redirExec.result.verification.reason}`)
  const redirTx = redirExec.result.transcript
  const redirProbeEntry = redirTx.entries!.find(e => e.step.arm === 'probe')!
  assert.equal(redirProbeEntry.hostRedirectCanary?.nonceStamp?.exchangeId, redirProbeEntry.exchangeId, 'redirect probe must carry exchangeId-bound child stamp')
  assert.equal(redirProbeEntry.hostRedirectCanary?.nonceStamp?.runId, redirRunId)
  // Negatives: cite exact redirect stamp on E2, route R2, run B, or with no runId -> ALL REJECT
  const e2RedirEntries = redirTx.entries!.map(e => e.step.arm === 'probe' ? { ...e, exchangeId: 'e2-other', step: { ...e.step, id: 'e2-other' } } : e)
  assert.equal(verifyReceipt(buildProofReceipt({ ...redirExec.receipt, exchangeIds: e2RedirEntries.map(e => e.exchangeId) }), { ...redirTx, entries: e2RedirEntries }, { runId: redirRunId }).confirmed, false, 'redirect stamp reused on E2 must reject')
  const r2RedirEntries = redirTx.entries!.map(e => ({ ...e, step: { ...e.step, route: '/auth/Other', pathAndQuery: e.step.pathAndQuery?.replace('/auth/Go', '/auth/Other') } }))
  assert.equal(verifyReceipt(buildProofReceipt({ ...redirExec.receipt, target: { ...redirExec.receipt.target, pathAndQuery: redirExec.receipt.target.pathAndQuery?.replace('/auth/Go', '/auth/Other') } }), { ...redirTx, entries: r2RedirEntries }, { runId: redirRunId }).confirmed, false, 'redirect stamp reused on route R2 must reject')
  assert.equal(verifyReceipt(redirExec.receipt, { ...redirTx, runId: 'run-B' }, { runId: 'run-B' }).confirmed, false, 'redirect stamp reused on run B must reject')
  assert.equal(verifyReceipt(redirExec.receipt, { entries: redirTx.entries }).confirmed, false, 'redirect without host runId must reject')

  // 5. N3' Self-service own-API-key readback (no tenant field, non-admin route, anon 401) -> MUST REJECT
  const selfKeyReceipt = buildProofReceipt({
    vulnClass: 'info_disclosure',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/me/keys' },
    exchangeIds: ['sk-anon', 'sk-me'],
    claimedDelta: 'Authenticated user reads their own API key on /api/me/keys.',
  })
  const selfKeyVerdict = verifyReceipt(selfKeyReceipt, {
    entries: [
      { exchangeId: 'sk-anon', origin: ORIGIN, step: mkStep({ id: 'sk-anon', arm: 'control', method: 'GET', route: '/api/me/keys', status: 401, actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }, body: '{"error":"unauthorized"}' }) },
      { exchangeId: 'sk-me', origin: ORIGIN, step: mkStep({ id: 'sk-me', arm: 'probe', method: 'GET', route: '/api/me/keys', status: 200, actor: { handle: 'alice', role: 'member', tenant: null, auth: 'bearer', sameSite: null }, body: '{"key":"sk_live_0123456789abcdef"}' }) },
    ],
  })
  assert.equal(selfKeyVerdict.confirmed, false, 'N3\': benign self-service API key readback on /api/me/keys must NOT get credential-pattern boundary credit')

  // 6. NonceLedger.bindStamp with persistPayload=false (payloadJson === null) preserves parent payloadDigest identically
  const nullPayloadLedger = new NonceLedger()
  const parentNoPayload = nullPayloadLedger.mintStamp({ runId: 'run-null-p', oracleId: 'timing', origin: ORIGIN, method: 'GET', route: '/api/t', param: 'q' }, { delayMs: 2_000 }, { persistPayload: false })
  const childNoPayload = nullPayloadLedger.bindStampToExchange(parentNoPayload, 'ex-null-1', 'probe')
  assert.ok(childNoPayload)
  assert.equal(childNoPayload.payloadDigest, parentNoPayload.payloadDigest, 'bindStamp with payloadJson=null must preserve parent payloadDigest without re-hashing')
  assert.ok(nullPayloadLedger.verifyStamp(childNoPayload, { runId: 'run-null-p', oracleId: 'timing', origin: ORIGIN, method: 'GET', route: '/api/t', param: 'q', armRole: 'probe', exchangeId: 'ex-null-1', payloadDigest: parentNoPayload.payloadDigest }))

  // 7. Missing runId at mint throws fail-closed
  assert.throws(() => defaultHostMintedOracle.mintTimingChallenge('sqli', 2_000), /runId/i)
  assert.throws(() => defaultHostMintedOracle.mintRedirectCanary('canary.kovo.invalid'), /runId/i)
  assert.throws(() => defaultHostMintedOracle.mintExpressionChallenge('ssti'), /runId/i)
  assert.throws(() => defaultHostMintedOracle.mintBooleanPair('1'), /runId/i)
})

// ============================================================================
// Test 10 (R3-05 C1a, C1b, C2): Strict caller-omission rejection, strictly
// monotonic bindStamp (E1/R1 -> R2/E2 returns null), and mandatory FloorRecipeDeps.runId
// ============================================================================

test('R3-16 Test 10 (C1a/C1b/C2): verifyStamp rejects omitted non-null dims, bindStamp is strictly monotonic, and floor recipes reject blank runId', async () => {
  const ledger = new NonceLedger()
  const runId = 'run-c1-strict-1'
  const parent = ledger.mintStamp(
    { runId, oracleId: 'timing', origin: ORIGIN, method: 'GET', route: '/api/R1', param: 'q' },
    { delayMs: 2_000 },
  )
  // Monotonic refinement: parent has armRole=null, exchangeId=null -> child fills both
  const bound = ledger.bindStamp(parent, { armRole: 'probe', exchangeId: 'E1' }, 'E1')
  assert.ok(bound, 'monotonic child filling null armRole/exchangeId must succeed')

  // C1(a): full expected tuple passes, omitting ANY non-null dimension fails closed
  const fullExpected = {
    runId, oracleId: 'timing' as const, origin: ORIGIN, method: 'GET',
    route: '/api/R1', param: 'q', armRole: 'probe', exchangeId: 'E1',
  }
  assert.ok(ledger.verifyStamp(bound, fullExpected), 'full expected tuple must verify')
  for (const omittedKey of ['origin', 'method', 'route', 'param', 'armRole', 'exchangeId'] as const) {
    const partial = { ...fullExpected }
    delete (partial as Record<string, unknown>)[omittedKey]
    assert.equal(
      ledger.verifyStamp(bound, partial),
      null,
      `C1(a): omitting bound dimension "${omittedKey}" must fail closed`,
    )
  }

  // C1(b): strictly monotonic bindStamp rejects overriding ANY non-null parent dimension
  assert.equal(ledger.bindStamp(bound, { route: '/api/R2' }, 'R2'), null, 're-binding E1/R1 stamp to route R2 must return null')
  assert.equal(ledger.bindStamp(bound, { exchangeId: 'E2' }, 'E2'), null, 're-binding E1/R1 stamp to exchange E2 must return null')
  assert.equal(ledger.bindStampToExchange(bound, 'E2'), null, 'bindStampToExchange on already-bound E1 stamp to E2 must return null')
  assert.equal(ledger.bindStamp(bound, { origin: 'https://other.example.invalid' }), null, 'overriding origin must return null')
  assert.equal(ledger.bindStamp(bound, { method: 'POST' }), null, 'overriding method must return null')
  assert.equal(ledger.bindStamp(bound, { param: 'other' }), null, 'overriding param must return null')
  assert.equal(ledger.bindStamp(bound, { armRole: 'control' }), null, 'overriding armRole must return null')
  assert.equal(ledger.bindStamp(bound, { route: null }), null, 'clearing non-null route to null must return null')
  assert.ok(ledger.bindStamp(bound, { route: '/api/R1', exchangeId: 'E1' }, 'E1'), 'idempotent repeat of identical parent dims succeeds')

  // C2: FloorRecipeDeps.runId is mandatory (blank/missing throws fail-closed)
  await assert.rejects(
    () => runCut3Recipe(cut3FloorRecipe('redirect', {
      origin: ORIGIN, method: 'GET', pathAndQuery: '/auth/Go?next=/home',
      controlPathAndQuery: '/auth/Go?next=/home', probePathAndQuery: '/auth/Go?next=https://{{redirectHost}}/ok',
      vulnClass: 'open_redirect', actor: { handle: 'alice', role: 'member', tenant: 'acme' },
    }), { runId: '', request: () => ({ status: 302, body: '' }) }),
    /runId/i,
    'C2: runCut3Recipe must throw fail-closed when FloorRecipeDeps.runId is empty',
  )
})
