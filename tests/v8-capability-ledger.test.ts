/**
 * v8 M0 CapabilityLedger unit & SQLite WAL persistence suite.
 *
 * Verifies:
 * - LOC budget (<= 900 LOC) and zero benchmark-literal contamination
 * - SQLite WAL persistence across close/reopen + shared DatabaseSync integration
 * - Strict `capability_only` quarantine fail-closed enforcement (app + SQLite CHECK)
 * - Zero raw secrets invariant + DerivedCapabilityHandle / SHA-256 digest enforcement
 * - 4-hop DAG lineage across all 4 causal binding kinds + monotonic timestamps + cycle rejection
 * - Attacker-origin provenance tracing (rejecting pre-seeded privileged roots & actor shortcuts)
 * - Negative-edge 2-strike branch pruning with order-independent precondition keys
 * - Bounded <= 2 KB hop-checkpoint brief export under normal and high-fanout stress
 */
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  ALWAYS_QUARANTINED_KINDS,
  CAPABILITY_KINDS,
  CAPABILITY_SURFACES,
  CAPABILITY_TEMPORAL_STATES,
  CAUSAL_EDGE_BINDING_KINDS,
  CapabilityLedger,
  CapabilityLedgerError,
  DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES,
  NEGATIVE_EDGE_REASONS,
  canonicalPreconditionKey,
  computeArtifactDigest,
  formatDerivedCapabilityHandle,
  isDerivedCapabilityHandle,
} from '../src/server/capability-ledger.ts'
import type { AddCapabilityInput } from '../src/server/capability-ledger.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const ledgerSourcePath = join(repoRoot, 'src/server/capability-ledger.ts')

function makeTempDbPath(t: { after: (fn: () => void) => void }): string {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-v8-ledger-'))
  t.after(() => { rmSync(dir, { recursive: true, force: true }) })
  return join(dir, 'capability-ledger.sqlite')
}

function capInput(overrides: Partial<AddCapabilityInput> & { capId: string }): AddCapabilityInput {
  return {
    kind: 'scoped_token',
    provenance: 'derived_hop',
    tenantScope: 'org_a',
    actorPersona: 'member_low',
    serviceOrigin: 'api_gateway',
    surface: 'http',
    artifactDigest: computeArtifactDigest(`artifact:${overrides.capId}`),
    artifactSummary: `Derived handle ${overrides.capId} observed on api_gateway`,
    ...overrides,
  }
}

function assertLedgerError(fn: () => unknown, expectedCode: string): CapabilityLedgerError {
  let caught: unknown
  try {
    fn()
  } catch (err) {
    caught = err
  }
  assert.ok(caught instanceof CapabilityLedgerError, `Expected CapabilityLedgerError('${expectedCode}'), got ${String(caught)}`)
  assert.equal(caught.code, expectedCode)
  return caught
}

test('module LOC budget (<= 900 LOC) and zero benchmark contamination', () => {
  const source = readFileSync(ledgerSourcePath, 'utf8')
  const lineCount = source.trimEnd().split('\n').length
  assert.ok(lineCount <= 900, `capability-ledger.ts must be <= 900 LOC, got ${lineCount}`)

  // Build forbidden benchmark-literal regex dynamically to verify src/server/ stays domain-neutral.
  const forbidden = [
    ['pay', 'grid'].join(''),
    ['ship', 'forge'].join(''),
    ['nexus', 'iam'].join(''),
    ['connect', 'hub'].join(''),
    ['vault', '.internal'].join(''),
    ['registry', '.internal'].join(''),
    ['billing', '.internal'].join(''),
    'PG-C', 'SF-C', 'NX-C', 'CH-C',
  ]
  for (const token of forbidden) {
    assert.equal(
      source.toLowerCase().includes(token.toLowerCase()),
      false,
      `capability-ledger.ts must not contain benchmark literal '${token}'`,
    )
  }

  assert.equal(CAPABILITY_KINDS.length, 10)
  assert.equal(CAPABILITY_SURFACES.length, 10)
  assert.equal(CAPABILITY_TEMPORAL_STATES.length, 6)
  assert.equal(CAUSAL_EDGE_BINDING_KINDS.length, 4)
  assert.equal(NEGATIVE_EDGE_REASONS.length, 3)
})

test('SQLite WAL persistence round-trips across close/reopen and supports shared DatabaseSync', (t) => {
  const dbPath = makeTempDbPath(t)
  const ledger1 = new CapabilityLedger(dbPath, { runId: 'run-alpha' })

  const journalRow = ledger1.db.prepare('PRAGMA journal_mode').get() as { journal_mode: string }
  assert.equal(journalRow.journal_mode.toLowerCase(), 'wal')

  // Insert one capability per domain-neutral kind across surfaces.
  CAPABILITY_KINDS.forEach((kind, idx) => {
    const capId = formatDerivedCapabilityHandle(`init${idx}`, kind)
    ledger1.addCapability(capInput({
      capId,
      kind,
      provenance: idx === 0 ? 'attacker_seed' : 'runtime_discovery',
      surface: CAPABILITY_SURFACES[idx % CAPABILITY_SURFACES.length]!,
      temporalState: CAPABILITY_TEMPORAL_STATES[idx % CAPABILITY_TEMPORAL_STATES.length]!,
      validityTtlMs: idx % 2 === 0 ? 60_000 : null,
      parentHopReceiptIds: idx > 0 ? [`hop_rcpt_${idx}`] : [],
      metadata: { slotIndex: idx, opaqueRefHandle: capId },
      createdAtMs: 1_000 + idx,
    }))
  })

  const rootId = formatDerivedCapabilityHandle('init0', 'identity_session')
  const tokId = formatDerivedCapabilityHandle('init1', 'scoped_token')
  ledger1.updateTemporalState(tokId, 'revoked', 2_500)
  ledger1.markTerminalEligible(rootId, 'oracle:dual_tenant_abac:rcpt_1', 2_600)

  ledger1.addCausalEdge({
    edgeId: 'edge_persist_1',
    preconditionCapIds: [rootId],
    actorContext: { persona: 'member_low', tenantScope: 'org_a', roleLabel: 'member' },
    hopReceiptId: 'hop_rcpt_persist_1',
    edgeBindingKind: 'value_binding',
    postconditionCapId: tokId,
    sourceTimestampMs: 1_000,
    targetTimestampMs: 1_500,
    bindingDigest: computeArtifactDigest('binding-1'),
    metadata: { injectedSlot: 'header' },
  })
  ledger1.recordNegativeEdge({
    preconditionCapIds: [rootId, tokId],
    targetSurfaceKey: 'POST /api/v1/exports',
    hypothesisClass: 'temporal_revocation',
    falsifiedByExchangeIds: ['ex_101'],
    reason: 'control_blocked_cleanly',
    notes: 'Primary REST surface returned 401 after revocation',
    timestampMs: 2_700,
  })
  ledger1.close()

  // Reopen from disk and verify exact round-trip.
  const ledger2 = new CapabilityLedger(dbPath, { runId: 'run-alpha' })
  t.after(() => ledger2.close())

  assert.equal(ledger2.listCapabilities().length, 10)
  const reopenedTok = ledger2.getCapability(tokId)!
  assert.equal(reopenedTok.temporalState, 'revoked')
  assert.equal(reopenedTok.updatedAtMs, 2_500)
  assert.equal(reopenedTok.promotionStatus, 'capability_only')

  const reopenedRoot = ledger2.getCapability(rootId)!
  assert.equal(reopenedRoot.promotionStatus, 'terminal_eligible')
  assert.equal(reopenedRoot.terminalImpactOracleVerified, true)
  assert.equal(reopenedRoot.metadata.terminalOracleRef, 'oracle:dual_tenant_abac:rcpt_1')

  const reopenedEdge = ledger2.getCausalEdge('edge_persist_1')!
  assert.deepEqual(reopenedEdge.preconditionCapIds, [rootId])
  assert.equal(reopenedEdge.postconditionCapId, tokId)
  assert.equal(reopenedEdge.edgeBindingKind, 'value_binding')

  const reopenedNeg = ledger2.getNegativeEdge([tokId, rootId], 'POST /api/v1/exports', 'temporal_revocation')!
  assert.equal(reopenedNeg.attemptCount, 1)
  assert.equal(reopenedNeg.pruned, false)
  assert.deepEqual(reopenedNeg.falsifiedByExchangeIds, ['ex_101'])

  assert.deepEqual(ledger2.getStats(), {
    totalNodes: 10,
    quarantinedNodes: 9,
    terminalEligibleNodes: 1,
    positiveEdges: 1,
    negativeEdges: 1,
    prunedBranches: 0,
  })

  // Shared DatabaseSync mode: isolated by runId and close() does not close external client.
  const sharedDb = new DatabaseSync(':memory:')
  t.after(() => sharedDb.close())
  const runA = new CapabilityLedger(sharedDb, { runId: 'run-a' })
  const runB = new CapabilityLedger(sharedDb, { runId: 'run-b' })
  runA.addCapability(capInput({ capId: 'cap:hop_a1:ref', kind: 'opaque_object_ref' }))
  assert.equal(runA.listCapabilities().length, 1)
  assert.equal(runB.listCapabilities().length, 0)
  runA.close()
  // External DB must remain usable after ledger.close().
  runB.addCapability(capInput({ capId: 'cap:hop_a1:ref', kind: 'opaque_object_ref' }))
  assert.equal(runB.listCapabilities().length, 1)
})

test('strict capability_only quarantine fails closed at app and SQLite CHECK layers', () => {
  const ledger = new CapabilityLedger(':memory:')

  for (const kind of ALWAYS_QUARANTINED_KINDS) {
    const capId = formatDerivedCapabilityHandle('q1', kind)
    // Reject explicit terminal_eligible at insert time even with oracle flag.
    assertLedgerError(() => ledger.addCapability(capInput({
      capId,
      kind,
      promotionStatus: 'terminal_eligible',
      terminalImpactOracleVerified: true,
    })), 'QUARANTINED_KIND')

    const node = ledger.addCapability(capInput({ capId, kind }))
    assert.equal(node.promotionStatus, 'capability_only')

    // Reject standalone promotion without a verified CompositeProofReceipt.
    assertLedgerError(() => ledger.assertPromotable(capId, false), 'CAPABILITY_QUARANTINED')
    assertLedgerError(() => ledger.assertPromotable(capId, false, { terminalImpactOracleVerified: true }), 'CAPABILITY_QUARANTINED')
    assertLedgerError(() => ledger.markTerminalEligible(capId, 'oracle:direct:1'), 'QUARANTINED_KIND')

    // Succeeds when composed into a verified terminal CompositeProofReceipt.
    const promoted = ledger.assertPromotable(capId, true)
    assert.equal(promoted.capId, capId)

    // Defense-in-depth SQLite CHECK constraint blocks raw SQL bypass.
    assert.throws(() => {
      ledger.db.prepare(
        "UPDATE capability_nodes SET promotion_status = 'terminal_eligible', terminal_impact_oracle_verified = 1 WHERE cap_id = ?",
      ).run(capId)
    }, /CHECK constraint failed/i)
  }

  // Non-quarantined intermediate node defaults to capability_only and requires explicit terminal oracle or composite receipt.
  const tokId = 'cap:hop_q2:scoped_pat'
  assertLedgerError(() => ledger.addCapability(capInput({
    capId: tokId,
    kind: 'scoped_token',
    promotionStatus: 'terminal_eligible',
    terminalImpactOracleVerified: false,
  })), 'UNVERIFIED_TERMINAL_PROMOTION')

  const tok = ledger.addCapability(capInput({ capId: tokId, kind: 'scoped_token' }))
  assert.equal(tok.promotionStatus, 'capability_only')
  assertLedgerError(() => ledger.assertPromotable(tokId, false), 'CAPABILITY_QUARANTINED')
  assert.equal(ledger.assertPromotable(tokId, true).capId, tokId)
  assert.equal(ledger.assertPromotable(tokId, false, { terminalImpactOracleVerified: true }).capId, tokId)

  const upgraded = ledger.markTerminalEligible(tokId, 'oracle:cryptographic_scope_replay:rcpt_9')
  assert.equal(upgraded.promotionStatus, 'terminal_eligible')
  assert.equal(ledger.assertPromotable(tokId, false).capId, tokId)
  ledger.close()
})

test('zero raw secrets invariant rejects raw credentials while allowing opaque handles and digests', () => {
  const ledger = new CapabilityLedger(':memory:')

  // Invalid handle & invalid digest rejected.
  assert.equal(isDerivedCapabilityHandle('cap:hop_h1:token'), true)
  assert.equal(isDerivedCapabilityHandle('raw-id-without-prefix'), false)
  assertLedgerError(() => ledger.addCapability(capInput({ capId: 'plain_token_1' })), 'INVALID_HANDLE')
  assertLedgerError(() => ledger.addCapability(capInput({ capId: 'cap:hop_s0:tok', artifactDigest: 'not-a-sha256' })), 'INVALID_DIGEST')

  // Synthetic non-live secret-shaped strings that must all be rejected.
  const syntheticJwt = [
    Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url'),
    Buffer.from('{"sub":"user_1","org":"org_a"}').toString('base64url'),
    'sig_synthetic_placeholder_bytes_0123456789',
  ].join('.')
  const syntheticPem = ['-----BEGIN ', 'PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0\n-----END ', 'PRIVATE KEY-----'].join('')
  const rawSamples: Array<{ label: string; summary?: string; metadata?: Record<string, unknown> }> = [
    { label: 'jwt in summary', summary: `Leaked token ${syntheticJwt}` },
    { label: 'bearer in summary', summary: 'Header Authorization: Bearer abcdef1234567890xyz' },
    { label: 'basic auth in summary', summary: 'Basic dXNlcjpwYXNzMTIzNDU2' },
    { label: 'cookie header in summary', summary: 'Cookie: sid=deadbeef12345678' },
    { label: 'cookie attrs in summary', summary: 'app_auth=xyz987654321; HttpOnly; Path=/' },
    { label: 'pem key in metadata', metadata: { pemBlock: syntheticPem } },
    { label: 'api key prefix in metadata', metadata: { detail: 'sk-or-v1-synthetic0000000000000000' } },
    { label: 'hmac kv in metadata', metadata: { nested: { note: 'hmac_secret=deadbeef0123456789' } } },
    { label: 'sensitive key raw value', metadata: { token: 'opaque_raw_secret_value_1234' } },
    { label: 'sensitive cookie key', metadata: { cookie: 'raw_cookie_value_1234' } },
    { label: 'handle field non-handle', metadata: { secretHandle: 'not_a_cap_handle' } },
  ]

  rawSamples.forEach((sample, idx) => {
    const err = assertLedgerError(() => ledger.addCapability(capInput({
      capId: `cap:hop_sec${idx}:slot`,
      artifactSummary: sample.summary ?? 'safe summary',
      metadata: sample.metadata ?? {},
    })), 'RAW_SECRET_REJECTED')
    // Error message must never echo the rejected secret payload.
    assert.equal(err.message.includes('abcdef1234567890xyz'), false, `Error echoed secret for ${sample.label}`)
    assert.equal(err.message.includes(syntheticJwt), false, `Error echoed JWT for ${sample.label}`)
    assert.equal(err.message.includes('opaque_raw_secret_value_1234'), false, `Error echoed raw key for ${sample.label}`)
  })

  // Opaque DerivedCapabilityHandle references inside summary & sensitive metadata keys are accepted.
  const clean = ledger.addCapability(capInput({
    capId: 'cap:hop_sec_ok:pat',
    artifactSummary: 'Scoped token sealed as cap:hop_sec_ok:pat (Bearer cap:hop_sec_ok:pat)',
    metadata: {
      token: 'cap:hop_sec_ok:pat',
      secretHandle: 'cap:hop_sec_ok:hmac',
      tokenType: 'scoped_pat',
      hasCookieFlag: true,
    },
  }))
  assert.equal(clean.capId, 'cap:hop_sec_ok:pat')
  assert.equal(clean.artifactDigest.length, 64)
  ledger.close()
})

test('4-hop causal DAG enforces all 4 binding kinds, monotonic timestamps, and cycle rejection', () => {
  const ledger = new CapabilityLedger(':memory:')
  const caps = [
    ledger.addCapability(capInput({ capId: 'cap:hop_0:ref', kind: 'opaque_object_ref', provenance: 'attacker_seed', surface: 'http' })),
    ledger.addCapability(capInput({ capId: 'cap:hop_1:salt', kind: 'signing_material', provenance: 'derived_hop', surface: 'async_job' })),
    ledger.addCapability(capInput({ capId: 'cap:hop_2:sig', kind: 'signed_artifact_or_url', provenance: 'derived_hop', surface: 'webhook' })),
    ledger.addCapability(capInput({ capId: 'cap:hop_3:state', kind: 'state_handle', provenance: 'derived_hop', surface: 'graphql' })),
    ledger.addCapability(capInput({ capId: 'cap:hop_4:sess', kind: 'identity_session', provenance: 'async_poll', surface: 'browser', actorPersona: 'owner_admin' })),
  ]

  // Valid 4-hop chain covering all 4 typed bindings + terminal-only edge.
  const e1 = ledger.addCausalEdge({
    edgeId: 'e_hop1',
    preconditionCapIds: [caps[0]!.capId],
    actorContext: { persona: 'member_low', tenantScope: 'org_a' },
    hopReceiptId: 'rcpt_hop1',
    edgeBindingKind: 'value_binding',
    postconditionCapId: caps[1]!.capId,
    sourceTimestampMs: 1_000,
    targetTimestampMs: 1_200,
  })
  const e2 = ledger.addCausalEdge({
    edgeId: 'e_hop2',
    preconditionCapIds: [caps[1]!.capId],
    actorContext: { persona: 'member_low', tenantScope: 'org_a' },
    hopReceiptId: 'rcpt_hop2',
    edgeBindingKind: 'derived_crypto_binding',
    postconditionCapId: caps[2]!.capId,
    sourceTimestampMs: 1_200,
    targetTimestampMs: 1_500,
  })
  const e3 = ledger.addCausalEdge({
    edgeId: 'e_hop3',
    preconditionCapIds: [caps[2]!.capId],
    actorContext: { persona: 'member_low', tenantScope: 'org_a' },
    hopReceiptId: 'rcpt_hop3',
    edgeBindingKind: 'state_transition_binding',
    postconditionCapId: caps[3]!.capId,
    sourceTimestampMs: 1_600,
    targetTimestampMs: 2_000,
  })
  const e4 = ledger.addCausalEdge({
    edgeId: 'e_hop4',
    preconditionCapIds: [caps[3]!.capId],
    actorContext: { persona: 'victim_bot', tenantScope: 'org_a' },
    hopReceiptId: 'rcpt_hop4',
    edgeBindingKind: 'async_pivot_binding',
    postconditionCapId: caps[4]!.capId,
    sourceTimestampMs: 2_100,
    targetTimestampMs: 2_600,
  })
  const eTerm = ledger.addCausalEdge({
    edgeId: 'e_terminal',
    preconditionCapIds: [caps[4]!.capId],
    actorContext: { persona: 'owner_admin', tenantScope: 'org_a' },
    hopReceiptId: 'rcpt_terminal',
    edgeBindingKind: 'value_binding',
    postconditionCapId: null,
    terminalImpact: 'cross_tenant_secret_exfiltration',
    sourceTimestampMs: 2_700,
    targetTimestampMs: 2_900,
  })

  assert.equal(e1.edgeBindingKind, 'value_binding')
  assert.equal(e2.edgeBindingKind, 'derived_crypto_binding')
  assert.equal(e3.edgeBindingKind, 'state_transition_binding')
  assert.equal(e4.edgeBindingKind, 'async_pivot_binding')
  assert.equal(eTerm.postconditionCapId, null)
  assert.equal(eTerm.terminalImpact, 'cross_tenant_secret_exfiltration')
  assert.equal(ledger.listCausalEdges({ terminalOnly: true }).length, 1)

  // Non-monotonic timestamp within edge rejected.
  assertLedgerError(() => ledger.addCausalEdge({
    preconditionCapIds: [caps[0]!.capId],
    actorContext: { persona: 'member_low' },
    hopReceiptId: 'rcpt_bad_ts1',
    edgeBindingKind: 'value_binding',
    terminalImpact: 'bad_ts',
    sourceTimestampMs: 3_000,
    targetTimestampMs: 2_999,
  }), 'NON_MONOTONIC_TIMESTAMP')

  // Cross-hop non-monotonic timestamp rejected (starts before upstream completed).
  assertLedgerError(() => ledger.addCausalEdge({
    preconditionCapIds: [caps[2]!.capId],
    actorContext: { persona: 'member_low' },
    hopReceiptId: 'rcpt_bad_ts2',
    edgeBindingKind: 'value_binding',
    terminalImpact: 'bad_upstream_ts',
    sourceTimestampMs: 1_499,
    targetTimestampMs: 2_000,
  }), 'NON_MONOTONIC_TIMESTAMP')

  // Self-loop rejected.
  assertLedgerError(() => ledger.addCausalEdge({
    preconditionCapIds: [caps[1]!.capId],
    actorContext: { persona: 'member_low' },
    hopReceiptId: 'rcpt_self_loop',
    edgeBindingKind: 'value_binding',
    postconditionCapId: caps[1]!.capId,
    sourceTimestampMs: 3_000,
    targetTimestampMs: 3_100,
  }), 'CYCLE_DETECTED')

  // 4-hop cycle (cap4 -> cap0) rejected without mutating DB.
  assertLedgerError(() => ledger.addCausalEdge({
    preconditionCapIds: [caps[4]!.capId],
    actorContext: { persona: 'owner_admin' },
    hopReceiptId: 'rcpt_cycle4',
    edgeBindingKind: 'value_binding',
    postconditionCapId: caps[0]!.capId,
    sourceTimestampMs: 3_000,
    targetTimestampMs: 3_100,
  }), 'CYCLE_DETECTED')

  // Wait: cap4 -> cap0 had targetTimestampMs 3100 > e_hop1.sourceTimestampMs 1000 so check pure cycle with fresh timestamps too.
  const cA = ledger.addCapability(capInput({ capId: 'cap:hop_cyc:a' }))
  const cB = ledger.addCapability(capInput({ capId: 'cap:hop_cyc:b' }))
  const cC = ledger.addCapability(capInput({ capId: 'cap:hop_cyc:c' }))
  ledger.addCausalEdge({
    preconditionCapIds: [cA.capId], actorContext: { persona: 'member_low' },
    hopReceiptId: 'rcpt_ca', edgeBindingKind: 'value_binding', postconditionCapId: cB.capId,
    sourceTimestampMs: 5_000, targetTimestampMs: 5_000,
  })
  ledger.addCausalEdge({
    preconditionCapIds: [cB.capId], actorContext: { persona: 'member_low' },
    hopReceiptId: 'rcpt_cb', edgeBindingKind: 'value_binding', postconditionCapId: cC.capId,
    sourceTimestampMs: 5_000, targetTimestampMs: 5_000,
  })
  assertLedgerError(() => ledger.addCausalEdge({
    preconditionCapIds: [cC.capId], actorContext: { persona: 'member_low' },
    hopReceiptId: 'rcpt_cc', edgeBindingKind: 'value_binding', postconditionCapId: cA.capId,
    sourceTimestampMs: 5_000, targetTimestampMs: 5_000,
  }), 'CYCLE_DETECTED')

  assert.equal(ledger.listCausalEdges().length, 7)
  ledger.close()
})

test('attacker-origin provenance verifies 4-hop escalation and rejects pre-seeded privileged shortcuts', () => {
  const ledger = new CapabilityLedger(':memory:')
  const attackers = ['member_low', 'member_org_b']

  // Valid 4-hop chain: member_low discovers ref -> escalates to owner_admin session -> pivots -> extracts artifact.
  const c0 = ledger.addCapability(capInput({ capId: 'cap:hop_p0:ref', kind: 'opaque_object_ref', actorPersona: 'member_low', provenance: 'attacker_seed' }))
  const c1 = ledger.addCapability(capInput({ capId: 'cap:hop_p1:sess', kind: 'identity_session', actorPersona: 'owner_admin', provenance: 'derived_hop' }))
  const c2 = ledger.addCapability(capInput({ capId: 'cap:hop_p2:state', kind: 'state_handle', actorPersona: 'owner_admin', provenance: 'derived_hop' }))
  const c3 = ledger.addCapability(capInput({ capId: 'cap:hop_p3:signed', kind: 'signed_artifact_or_url', actorPersona: 'owner_admin', provenance: 'derived_hop' }))
  const c4 = ledger.addCapability(capInput({ capId: 'cap:hop_p4:reach', kind: 'internal_reach_handle', actorPersona: 'owner_admin', provenance: 'derived_hop' }))

  ledger.addCausalEdge({
    edgeId: 'p_e1', preconditionCapIds: [c0.capId], actorContext: { persona: 'member_low' },
    hopReceiptId: 'r1', edgeBindingKind: 'value_binding', postconditionCapId: c1.capId,
    sourceTimestampMs: 100, targetTimestampMs: 200,
  })
  ledger.addCausalEdge({
    edgeId: 'p_e2', preconditionCapIds: [c1.capId], actorContext: { persona: 'owner_admin' },
    hopReceiptId: 'r2', edgeBindingKind: 'state_transition_binding', postconditionCapId: c2.capId,
    sourceTimestampMs: 200, targetTimestampMs: 300,
  })
  ledger.addCausalEdge({
    edgeId: 'p_e3', preconditionCapIds: [c2.capId], actorContext: { persona: 'owner_admin' },
    hopReceiptId: 'r3', edgeBindingKind: 'derived_crypto_binding', postconditionCapId: c3.capId,
    sourceTimestampMs: 300, targetTimestampMs: 400,
  })
  ledger.addCausalEdge({
    edgeId: 'p_e4', preconditionCapIds: [c3.capId], actorContext: { persona: 'owner_admin' },
    hopReceiptId: 'r4', edgeBindingKind: 'async_pivot_binding', postconditionCapId: c4.capId,
    sourceTimestampMs: 400, targetTimestampMs: 500,
  })

  const validTrace = ledger.traceProvenanceToAttacker(c4.capId, attackers)
  assert.equal(validTrace.valid, true)
  assert.equal(validTrace.hopDepth, 4)
  assert.deepEqual(validTrace.rootCapIds, [c0.capId])
  assert.deepEqual(validTrace.attackerRootPersonas, ['member_low'])
  assert.deepEqual(validTrace.pathEdgeIds, ['p_e1', 'p_e2', 'p_e3', 'p_e4'])
  assert.equal(validTrace.violations.length, 0)

  // Shortcut 1: Pre-seeded privileged root persona (owner_admin) not in attackerPersonas.
  const privRoot = ledger.addCapability(capInput({
    capId: 'cap:hop_sc1:priv_root', kind: 'identity_session', actorPersona: 'owner_admin', provenance: 'attacker_seed',
  }))
  const scTarget1 = ledger.addCapability(capInput({
    capId: 'cap:hop_sc1:target', kind: 'scoped_token', actorPersona: 'owner_admin', provenance: 'derived_hop',
  }))
  ledger.addCausalEdge({
    edgeId: 'sc_e1', preconditionCapIds: [privRoot.capId], actorContext: { persona: 'owner_admin' },
    hopReceiptId: 'r_sc1', edgeBindingKind: 'value_binding', postconditionCapId: scTarget1.capId,
    sourceTimestampMs: 600, targetTimestampMs: 700,
  })
  const sc1Trace = ledger.traceProvenanceToAttacker(scTarget1.capId, attackers)
  assert.equal(sc1Trace.valid, false)
  assert.ok(sc1Trace.violations.some(v => v.code === 'preseeded_privileged_root' && v.persona === 'owner_admin'))

  // Shortcut 2: Multi-precondition join smuggling a pre-seeded privileged root alongside attacker root.
  const scTarget2 = ledger.addCapability(capInput({
    capId: 'cap:hop_sc2:target', kind: 'scoped_token', actorPersona: 'member_low', provenance: 'derived_hop',
  }))
  ledger.addCausalEdge({
    edgeId: 'sc_e2', preconditionCapIds: [c0.capId, privRoot.capId], actorContext: { persona: 'member_low' },
    hopReceiptId: 'r_sc2', edgeBindingKind: 'value_binding', postconditionCapId: scTarget2.capId,
    sourceTimestampMs: 600, targetTimestampMs: 700,
  })
  const sc2Trace = ledger.traceProvenanceToAttacker(scTarget2.capId, attackers)
  assert.equal(sc2Trace.valid, false)
  assert.ok(sc2Trace.violations.some(v => v.code === 'preseeded_privileged_root'))

  // Shortcut 3: Attacker root exists, but edge is executed directly by owner_admin without derived authority.
  const scTarget3 = ledger.addCapability(capInput({
    capId: 'cap:hop_sc3:target', kind: 'scoped_token', actorPersona: 'owner_admin', provenance: 'derived_hop',
  }))
  ledger.addCausalEdge({
    edgeId: 'sc_e3', preconditionCapIds: [c0.capId], actorContext: { persona: 'owner_admin' },
    hopReceiptId: 'r_sc3', edgeBindingKind: 'value_binding', postconditionCapId: scTarget3.capId,
    sourceTimestampMs: 600, targetTimestampMs: 700,
  })
  const sc3Trace = ledger.traceProvenanceToAttacker(scTarget3.capId, attackers)
  assert.equal(sc3Trace.valid, false)
  assert.ok(sc3Trace.violations.some(v => v.code === 'privileged_actor_shortcut' && v.edgeId === 'sc_e3'))

  // Alternative-path resilience: adding a valid attacker-origin edge to scTarget3 makes provenance valid.
  ledger.addCausalEdge({
    edgeId: 'sc_e3_legit', preconditionCapIds: [c1.capId], actorContext: { persona: 'owner_admin' },
    hopReceiptId: 'r_sc3_legit', edgeBindingKind: 'value_binding', postconditionCapId: scTarget3.capId,
    sourceTimestampMs: 700, targetTimestampMs: 800,
  })
  const recovered = ledger.traceProvenanceToAttacker(scTarget3.capId, attackers)
  assert.equal(recovered.valid, true)
  assert.deepEqual(recovered.rootCapIds, [c0.capId])
  ledger.close()
})

test('negative edges enforce 2-strike pruning with canonical precondition keys and forcePrune', () => {
  const ledger = new CapabilityLedger(':memory:')
  const a = 'cap:hop_n1:a'
  const b = 'cap:hop_n2:b'
  const c = 'cap:hop_n3:c'
  assert.equal(canonicalPreconditionKey([b, a, a]), canonicalPreconditionKey([a, b]))

  assert.equal(ledger.isBranchPruned([a, b], 'POST /api/promote', 'scope_escalation'), false)

  // Strike 1: recorded, not yet pruned.
  const strike1 = ledger.recordNegativeEdge({
    preconditionCapIds: [a, b],
    targetSurfaceKey: 'POST /api/promote',
    hypothesisClass: 'scope_escalation',
    falsifiedByExchangeIds: ['ex_1'],
    reason: 'control_blocked_cleanly',
    timestampMs: 1_000,
  })
  assert.equal(strike1.attemptCount, 1)
  assert.equal(strike1.pruned, false)
  assert.equal(ledger.isBranchPruned([b, a], 'POST /api/promote', 'scope_escalation'), false)

  // Strike 2 with reversed precondition order: triggers 2-strike prune and merges exchange IDs.
  const strike2 = ledger.recordNegativeEdge({
    preconditionCapIds: [b, a],
    targetSurfaceKey: 'POST /api/promote',
    hypothesisClass: 'scope_escalation',
    falsifiedByExchangeIds: ['ex_2', 'ex_1'],
    reason: 'invariant_enforced_hardened',
    timestampMs: 2_000,
  })
  assert.equal(strike2.attemptCount, 2)
  assert.equal(strike2.pruned, true)
  assert.equal(strike2.reason, 'invariant_enforced_hardened')
  assert.deepEqual(strike2.falsifiedByExchangeIds, ['ex_1', 'ex_2'])
  assert.equal(ledger.isBranchPruned([a, b], 'POST /api/promote', 'scope_escalation'), true)

  // Unlocking an additional capability creates a distinct unpruned branch.
  assert.equal(ledger.isBranchPruned([a, b, c], 'POST /api/promote', 'scope_escalation'), false)

  // Force-prune on strike 1 (verified decoy guard).
  const decoy = ledger.recordNegativeEdge({
    preconditionCapIds: [a],
    targetSurfaceKey: 'GET /api/internal-proxy',
    hypothesisClass: 'ssrf_pivot',
    falsifiedByExchangeIds: ['ex_decoy_1'],
    reason: 'decoy_guard_verified',
    forcePrune: true,
    timestampMs: 2_500,
  })
  assert.equal(decoy.attemptCount, 1)
  assert.equal(decoy.pruned, true)
  assert.equal(ledger.isBranchPruned([a], 'GET /api/internal-proxy', 'ssrf_pivot'), true)
  assert.equal(ledger.listNegativeEdges({ prunedOnly: true }).length, 2)
  ledger.close()
})

test('buildHopCheckpointBrief formats <= 2 KB briefs accurately and truncates safely under stress', () => {
  const ledger = new CapabilityLedger(':memory:')

  const ids: string[] = []
  for (let i = 0; i < 6; i++) {
    const id = formatDerivedCapabilityHandle(`b${i}`, `slot${i}`)
    ids.push(id)
    ledger.addCapability(capInput({
      capId: id,
      kind: i === 0 ? 'opaque_object_ref' : 'state_handle',
      provenance: i === 0 ? 'attacker_seed' : 'derived_hop',
      artifactSummary: i === 5
        ? 'Verified state transition checkpoint with extended operational details '.repeat(25)
        : `Hop ${i} derived capability`,
    }))
    if (i > 0) {
      ledger.addCausalEdge({
        edgeId: `b_edge_${i}`,
        preconditionCapIds: [ids[i - 1]!],
        actorContext: { persona: 'member_low' },
        hopReceiptId: `rcpt_b_${i}`,
        edgeBindingKind: CAUSAL_EDGE_BINDING_KINDS[(i - 1) % CAUSAL_EDGE_BINDING_KINDS.length]!,
        postconditionCapId: id,
        sourceTimestampMs: i * 100,
        targetTimestampMs: i * 100 + 50,
      })
    }
  }

  // Normal compact brief at hop 2 stays untruncated and well under 2 KB (unified v8.hop_checkpoint.v1 schema).
  const normalBrief = ledger.buildHopCheckpointBrief(ids[2]!)
  const normalBytes = Buffer.byteLength(JSON.stringify(normalBrief), 'utf8')
  assert.equal(normalBrief.schema, 'v8.hop_checkpoint.v1')
  assert.equal(normalBrief.branchKey, ids[2])
  assert.equal(normalBrief.depth, 2)
  assert.equal(normalBrief.truncated, false)
  assert.equal(normalBrief.doNotRediscover, true)
  assert.equal(normalBrief.verifiedHops.length, 3)
  assert.ok(normalBrief.capabilityHandles.includes(ids[2]!))
  assert.ok(normalBytes <= DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES, `Expected <= 2048 B, got ${normalBytes} B`)

  // Stress brief at hop 5 with 25 pruned branches + huge summary strictly fits <= 2048 B and <= 768 B.
  for (let j = 0; j < 25; j++) {
    ledger.recordNegativeEdge({
      preconditionCapIds: [ids[5]!],
      targetSurfaceKey: `POST /api/v1/resource-surface-long-endpoint-name-${j}`,
      hypothesisClass: `hypothesis_class_variant_${j}`,
      falsifiedByExchangeIds: [`ex_stress_${j}`],
      reason: 'invariant_enforced_hardened',
      forcePrune: true,
    })
  }

  const stressDefault = ledger.buildHopCheckpointBrief(ids[5]!, 2048)
  const stressDefaultBytes = Buffer.byteLength(JSON.stringify(stressDefault), 'utf8')
  assert.equal(stressDefault.schema, 'v8.hop_checkpoint.v1')
  assert.equal(stressDefault.branchKey, ids[5])
  assert.equal(stressDefault.depth, 5)
  assert.equal(stressDefault.truncated, true)
  assert.ok(stressDefaultBytes <= 2048, `Expected <= 2048 B, got ${stressDefaultBytes} B`)

  const stressTight = ledger.buildHopCheckpointBrief(ids[5]!, 768)
  const stressTightBytes = Buffer.byteLength(JSON.stringify(stressTight), 'utf8')
  assert.equal(stressTight.schema, 'v8.hop_checkpoint.v1')
  assert.equal(stressTight.truncated, true)
  assert.ok(stressTightBytes <= 768, `Expected <= 768 B, got ${stressTightBytes} B`)

  assertLedgerError(() => ledger.buildHopCheckpointBrief(ids[5]!, 100), 'INVALID_ARGUMENT')
  assertLedgerError(() => ledger.buildHopCheckpointBrief('cap:hop_missing:x'), 'CAPABILITY_NOT_FOUND')
  ledger.close()
})
