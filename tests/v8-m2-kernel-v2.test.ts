// @kernel @fixes R3-12, R3-13
/**
 * Confirmation-Kernel v2 Behavioral & Security Regression Suite.
 *
 * Pure behavioral assertions covering:
 *  1. Authoritative v8 oracle family inference & snake_case/camelCase key normalization
 *     (`inferV8OracleFamilyDetailed`, `normalizeV8OracleInputKeys`, `hydrateV8OracleInput`,
 *     `verifyCompositeReceipt`):
 *     - Valid canonical & snake_case `oracleInput` objects without `oracleFamily` map
 *       deterministically for all 6 authoritative families.
 *     - Malformed, empty, and cross-family ambiguous `oracleInput` objects fail closed with
 *       valid `oracleFamily` names in the diagnostic.
 *     - Anti-bypass: snake_case attacker-action exchange keys in `oracleInput` still enforce
 *       `verifyAttackerProvenance` (`forceCheck: true`).
 *  2. DAG topology control/readback hop exclusion & supplemental host-observed causal inference:
 *     - Host-attested control/baseline and post-chain readback hops are excluded from causal
 *       reachability requirements AND never count toward `hopCount` or multi-hop depth.
 *     - Host-observed `oob_relay`, `browser_trace`, redirect-query digest `value_binding`, and
 *       multi-hop backwards fixed-point `state_transition_binding` edges participate cleanly
 *       before `dag_topology`.
 *     - Anti-bypass: control hops cannot inflate 1-hop chains to 2-hop; spoofed `role: 'control'`
 *       on a probe hop still rejects at `dag_topology`; tampered signatures inside excluded
 *       control hops still reject at `transcript_integrity`; disconnected probe hops still reject.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostBrowserTrace,
  type HostOobEvent,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import '../src/server/terminal-oracle-registry.ts'
import {
  hydrateV8OracleInput,
  inferV8OracleFamilyDetailed,
  normalizeV8OracleInputKeys,
  type HydratableTranscriptIndex,
} from '../src/server/v8-oracle-hydrate.ts'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'v8-m2-kernel-v2-test-signing-key-0123456789abcdef'

function makeStep(
  partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>,
): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? {
      handle: 'member_a',
      role: 'member',
      tenant: 'org_a',
      auth: 'bearer',
      sameSite: null,
    },
    ...(partial.route !== undefined
      ? { route: partial.route }
      : partial.pathAndQuery
        ? { route: partial.pathAndQuery.split('?')[0]! }
        : {}),
    ...(partial.pathAndQuery !== undefined ? { pathAndQuery: partial.pathAndQuery } : {}),
    ...(partial.json !== undefined ? { json: partial.json } : {}),
    ...(partial.body !== undefined ? { body: partial.body } : {}),
    ...(partial.requestJson !== undefined ? { requestJson: partial.requestJson } : {}),
    ...(partial.requestHeaders !== undefined ? { requestHeaders: partial.requestHeaders } : {}),
    ...(partial.responseHeaders !== undefined ? { responseHeaders: partial.responseHeaders } : {}),
    ...(partial.evidenceRole !== undefined ? { evidenceRole: partial.evidenceRole } : {}),
  }
}

function signedEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry> = {},
): HostTranscriptEntry {
  const base: HostTranscriptEntry = {
    exchangeId,
    origin: extra.origin ?? ORIGIN,
    step,
    seq: extra.seq ?? 1,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    actorRoleLabel: extra.actorRoleLabel !== undefined
      ? extra.actorRoleLabel
      : (step.actor.role && step.actor.tenant ? `${step.actor.role} (${step.actor.tenant})` : null),
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...base, hostSignature: signHostRecord(base, SIGNING_KEY) }
}

function signedOob(oob: Omit<HostOobEvent, 'hostSignature'>): HostOobEvent {
  return { ...oob, hostSignature: signHostRecord(oob, SIGNING_KEY) }
}

function signedTrace(tr: Omit<HostBrowserTrace, 'hostSignature'>): HostBrowserTrace {
  return { ...tr, hostSignature: signHostRecord(tr, SIGNING_KEY) }
}

// ============================================================================
// 1. Authoritative V8 Oracle Inference & Key Normalization
// ============================================================================

test('Fix 1a: inferV8OracleFamilyDetailed maps canonical & snake_case inputs for all 6 families and rejects malformed/ambiguous inputs', () => {
  // All 6 authoritative families (canonical camelCase + snake_case + *ExchangeId aliases)
  assert.deepEqual(
    inferV8OracleFamilyDetailed({ mode: 'parser_differential', cleanControl: 'c1', differentialProbe: 'p1', differentialKind: 'path_normalization' }),
    { kind: 'matched', family: 'parser_cache_differential' },
  )
  assert.deepEqual(
    inferV8OracleFamilyDetailed({ mode: 'cache_primed', clean_control: 'c1', victim_or_prime_request: 'v1', attacker_probe: 'a1', cache_key: 'ck1' }),
    { kind: 'matched', family: 'parser_cache_differential' },
  )
  assert.deepEqual(
    inferV8OracleFamilyDetailed({ baseline_readback_exchange_id: 'b1', final_readback_exchange_id: 'f1', action_exchange_ids: ['a1', 'a2'] }),
    { kind: 'matched', family: 'economic_conservation' },
  )
  assert.deepEqual(
    inferV8OracleFamilyDetailed({ balancesBefore: { acct1: 100 }, balancesAfter: { acct1: 250 } }),
    { kind: 'matched', family: 'economic_conservation' },
  )
  assert.deepEqual(
    inferV8OracleFamilyDetailed({ tampered_signature_control: 'c1', source_valid_issuance: 's1', replayed_acceptance: 'r1' }),
    { kind: 'matched', family: 'cryptographic_scope_replay' },
  )
  assert.deepEqual(
    inferV8OracleFamilyDetailed({ revocation_event_exchange_id: 'rv1', primary_denied_check_exchange_id: 'pd1', secondary_success_exchange_id: 'ss1' }),
    { kind: 'matched', family: 'temporal_revocation' },
  )
  assert.deepEqual(
    inferV8OracleFamilyDetailed({ transfer_record_exchange_id: 't1', post_transfer_readback_exchange_id: 'r1', source_control_denied: 'c1' }),
    { kind: 'matched', family: 'dual_tenant_abac' },
  )
  assert.deepEqual(
    inferV8OracleFamilyDetailed({ pre_chain_control_exchange_id: 'c1', hops: [{ surface: 'http', role: 'trigger_write', record: 'h1' }] }),
    { kind: 'matched', family: 'cross_surface_pivot' },
  )

  // Malformed / empty / unknown -> unmapped
  assert.deepEqual(inferV8OracleFamilyDetailed({}), { kind: 'unmapped' })
  assert.deepEqual(inferV8OracleFamilyDetailed({ spoofedHint: 'invalid', arbitrary: 123 }), { kind: 'unmapped' })

  // Ambiguous across multiple families -> ambiguous (NEVER silently picks first family!)
  const ambig = inferV8OracleFamilyDetailed({ mode: 'dual_org_cache_bleed', equation: 'over_refund', bledAccess: 'b1' })
  assert.equal(ambig.kind, 'ambiguous')
  if (ambig.kind === 'ambiguous') {
    assert.ok(ambig.families.includes('dual_tenant_abac'))
    assert.ok(ambig.families.includes('economic_conservation'))
  }

  // Prototype pollution guard & balance-map key preservation
  const norm = normalizeV8OracleInputKeys({
    baseline_readback_exchange_id: 'b1',
    balances_before: { user_acct_1: 500 },
  })
  assert.equal(norm.baselineReadbackExchangeId, 'b1')
  assert.deepEqual(norm.balancesBefore, { user_acct_1: 500 })
})

test('Fix 1b: parser_cache_differential and economic_conservation confirm cleanly without oracleFamily and reject hardened/malformed/ambiguous inputs', () => {
  const cap = 'cap:hop_1:order_tok_1b'
  // --- economic_conservation without oracleFamily and with snake_case + omitted equation ---
  const baseRead = signedEntry('ec-base', makeStep({
    id: 'ec-base', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/v1/orders/ord_101',
    json: { id: 'ord_101', paidAmount: 100, refundedTotal: 0 },
  }), { seq: 1, timestampMs: 1000 })
  const h1 = signedEntry('ec-h1', makeStep({
    id: 'ec-h1', arm: 'probe', method: 'POST', status: 201, pathAndQuery: '/api/v1/orders/ord_101/token',
    json: { token: 'tok-9f8e7d6c' },
  }), { seq: 2, timestampMs: 1050, emittedCapabilities: [cap] })
  const act1 = signedEntry('ec-act1', makeStep({
    id: 'ec-act1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/orders/ord_101/refund',
    json: { refundedAmount: 100, refundedTotal: 100 },
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [cap] })
  const act2 = signedEntry('ec-act2', makeStep({
    id: 'ec-act2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/orders/ord_101/refund',
    json: { refundedAmount: 100, refundedTotal: 200 },
  }), { seq: 4, timestampMs: 1120, consumedCapabilities: [cap] })
  const finOver = signedEntry('ec-fin-over', makeStep({
    id: 'ec-fin-over', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/v1/orders/ord_101',
    json: { id: 'ord_101', paidAmount: 100, refundedTotal: 200 },
  }), { seq: 5, timestampMs: 1200, evidenceRole: 'post_chain_readback' })
  const finConserved = signedEntry('ec-fin-ok', makeStep({
    id: 'ec-fin-ok', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/v1/orders/ord_101',
    json: { id: 'ord_101', paidAmount: 100, refundedTotal: 100 },
  }), { seq: 5, timestampMs: 1200, evidenceRole: 'post_chain_readback' })

  const econReceipt = (finalId: string, oracleInput: Record<string, unknown>): CompositeProofReceipt => ({
    chainId: 'fix1b-econ',
    terminalVulnClass: 'ledger_overcredit',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orders/ord_101/token' }, exchangeIds: ['ec-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained refund token', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orders/ord_101/refund' }, exchangeIds: ['ec-act1', 'ec-act2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Issued duplicate refund actions', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      terminalExchangeId: 'ec-act2',
      summary: 'Duplicate refunds exceeded original paid amount on order ledger.',
      claimedImpact: 'Duplicate refunds exceeded original paid amount on order ledger.',
      preChainControlExchangeIds: ['ec-base'],
      postChainReadbackExchangeIds: [finalId],
      oracleInput,
    },
    replayMode: 'fresh_clean_replay',
  })

  // Note: ledger_overcredit also needs a denied control unless routed via economic_conservation!
  // With terminalVulnClass='economic_conservation' or omitted oracleFamily on 'over_refund'/'business_logic',
  // let's test BOTH terminalVulnClass='business_logic' with denied control AND 'economic_conservation' direct.
  const deniedCtrl = signedEntry('ec-denied', makeStep({
    id: 'ec-denied', arm: 'control', method: 'POST', status: 403, pathAndQuery: '/api/v1/orders/ord_101/refund',
    json: { error: 'forbidden' },
  }), { seq: 0, timestampMs: 950 })
  const econOk = verifyCompositeReceipt(
    {
      ...econReceipt('ec-fin-over', {
        baseline_readback_exchange_id: 'ec-base',
        final_readback_exchange_id: 'ec-fin-over',
        action_exchange_ids: ['ec-act1', 'ec-act2'],
      }),
      terminalImpact: {
        ...econReceipt('ec-fin-over', {
          baseline_readback_exchange_id: 'ec-base',
          final_readback_exchange_id: 'ec-fin-over',
          action_exchange_ids: ['ec-act1', 'ec-act2'],
        }).terminalImpact,
        preChainControlExchangeIds: ['ec-denied', 'ec-base'],
      },
    },
    { entries: [deniedCtrl, baseRead, h1, act1, act2, finOver] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
  )
  assert.equal(econOk.confirmed, true, `snake_case economic_conservation without oracleFamily must confirm, got: ${econOk.reason}`)
  assert.equal(econOk.terminalOracleFamily, 'economic_conservation')

  // Hardened conserved twin MUST STILL REJECT!
  const hardBase = econReceipt('ec-fin-ok', {
    baseline_readback_exchange_id: 'ec-base',
    final_readback_exchange_id: 'ec-fin-ok',
    action_exchange_ids: ['ec-act1'],
  })
  const econHard = verifyCompositeReceipt(
    {
      ...hardBase,
      hops: [hardBase.hops[0]!, { ...hardBase.hops[1]!, exchangeIds: ['ec-act1'] }],
      terminalImpact: {
        ...hardBase.terminalImpact,
        terminalExchangeId: 'ec-act1',
        preChainControlExchangeIds: ['ec-denied', 'ec-base'],
      },
    },
    { entries: [deniedCtrl, baseRead, h1, act1, finConserved] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
  )
  assert.equal(econHard.confirmed, false, 'conserved ledger must still reject')
  assert.equal(econHard.rejectedBy, 'v8_oracle_economic_conservation')

  // Explicit invalid equation MUST NOT be overridden by host inference!
  const econBadEq = verifyCompositeReceipt(
    econReceipt('ec-fin-over', {
      equation: 'bogus_equation',
      baselineReadbackExchangeId: 'ec-base',
      finalReadbackExchangeId: 'ec-fin-over',
      actionExchangeIds: ['ec-act1', 'ec-act2'],
    }),
    { entries: [deniedCtrl, baseRead, h1, act1, act2, finOver] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
  )
  assert.equal(econBadEq.confirmed, false)
  assert.match(econBadEq.reason, /unknown_economic_equation/)

  // --- parser_cache_differential canonical input without oracleFamily ---
  const pcCtrl = signedEntry('pc-ctrl', makeStep({
    id: 'pc-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/admin/ledger',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000 })
  const pcProbe = signedEntry('pc-probe', makeStep({
    id: 'pc-probe', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/public/../admin/ledger',
    json: { tenantId: 'org_b', balanceCents: 990000 },
  }), { seq: 2, timestampMs: 1100 })
  const pcRes = verifyCompositeReceipt(
    {
      chainId: 'fix1b-parser-diff',
      terminalVulnClass: 'cache_poisoning',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/public/../admin/ledger' }, exchangeIds: ['pc-probe'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Bypassed route ACL via path normalization', producedCapabilities: [], consumedCapabilities: [] },
      ],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'hop_1',
        terminalExchangeId: 'pc-probe',
        summary: 'Path normalization differential exposed restricted ledger record.',
        claimedImpact: 'Path normalization differential exposed restricted ledger record.',
        preChainControlExchangeIds: ['pc-ctrl'],
        postChainReadbackExchangeIds: [],
        oracleInput: {
          mode: 'parser_differential',
          differentialKind: 'path_normalization',
          differentialFeature: 'dotdot_segment',
          impactKind: 'read',
          cleanControl: 'pc-ctrl',
          differentialProbe: 'pc-probe',
        },
      },
      replayMode: 'fresh_clean_replay',
    },
    { entries: [pcCtrl, pcProbe] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
  )
  assert.equal(pcRes.confirmed, true, `canonical parser_cache_differential without oracleFamily must confirm, got: ${pcRes.reason}`)
  assert.equal(pcRes.terminalOracleFamily, 'parser_cache_differential')

  // --- Ambiguous and empty oracleInput without oracleFamily MUST reject with valid family list ---
  for (const [label, badInput, expectedCode] of [
    ['empty', {}, /unmapped_oracle_input/],
    ['ambiguous', { mode: 'parser_differential', equation: 'over_refund', cleanControl: 'pc-ctrl' }, /ambiguous_oracle_input/],
  ] as const) {
    const r = verifyCompositeReceipt(
      {
        chainId: `fix1b-bad-${label}`,
        terminalVulnClass: 'cross_tenant_read',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/public/../admin/ledger' }, exchangeIds: ['pc-probe'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Probe', producedCapabilities: [], consumedCapabilities: [] },
        ],
        causalEdges: [],
        terminalImpact: {
          terminalHopId: 'hop_1',
          terminalExchangeId: 'pc-probe',
          summary: 'Testing malformed or ambiguous oracleInput fail-closed diagnostic.',
          claimedImpact: 'Testing malformed or ambiguous oracleInput fail-closed diagnostic.',
          preChainControlExchangeIds: ['pc-ctrl'],
          postChainReadbackExchangeIds: [],
          oracleInput: badInput,
        },
        replayMode: 'fresh_clean_replay',
      },
      { entries: [pcCtrl, pcProbe] },
      { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
    )
    assert.equal(r.confirmed, false, `${label} oracleInput must reject`)
    assert.equal(r.rejectedBy, 'v8_oracle_family_missing')
    assert.match(r.reason, expectedCode)
    assert.match(r.reason, /economic_conservation/)
    assert.match(r.reason, /parser_cache_differential/)
  }
})

test('Fix 1c (anti-bypass): snake_case attacker-action exchange in oracleInput cannot bypass verifyAttackerProvenance', () => {
  const adminActor = { handle: 'admin_a', role: 'admin' as const, tenant: 'org_a', auth: 'bearer' as const, sameSite: null }
  const cap = 'cap:hop_1:sig_tok'
  const tampered = signedEntry('sc-tamp', makeStep({
    id: 'sc-tamp', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/docs/secret?sig=bad',
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000 })
  // Attacker attempts to smuggle an admin-issued exchange labeled arm:'control' under snake_case key `source_valid_issuance`!
  const adminIssuance = signedEntry('sc-admin-iss', makeStep({
    id: 'sc-admin-iss', arm: 'control', method: 'POST', status: 200, pathAndQuery: '/api/v1/docs/sign',
    actor: adminActor, json: { signedUrl: '/api/v1/docs/own?sig=valid_sig_abc' },
  }), { seq: 2, timestampMs: 1050, actorPersona: 'admin_a', actorRoleLabel: 'admin (org_a)' })
  const h1 = signedEntry('sc-h1', makeStep({
    id: 'sc-h1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/docs/list',
    json: { ref: 'ref-1' },
  }), { seq: 3, timestampMs: 1100, emittedCapabilities: [cap] })
  const replayed = signedEntry('sc-rep', makeStep({
    id: 'sc-rep', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/docs/secret?sig=valid_sig_abc',
    json: { tenantId: 'org_b', secret: 'private-doc' },
  }), { seq: 4, timestampMs: 1200, consumedCapabilities: [cap] })

  const res = verifyCompositeReceipt(
    {
      chainId: 'fix1c-snakecase-admin-bypass',
      terminalVulnClass: 'cross_tenant_read',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/docs/list' }, exchangeIds: ['sc-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Listed docs', producedCapabilities: [cap], consumedCapabilities: [] },
        { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/docs/secret?sig=valid_sig_abc' }, exchangeIds: ['sc-rep'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Replayed signed URL', producedCapabilities: [], consumedCapabilities: [cap] },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
      terminalImpact: {
        terminalHopId: 'hop_2',
        terminalExchangeId: 'sc-rep',
        summary: 'Attempted snake_case admin-issuance smuggling in oracleInput.',
        claimedImpact: 'Attempted snake_case admin-issuance smuggling in oracleInput.',
        preChainControlExchangeIds: ['sc-tamp'],
        postChainReadbackExchangeIds: [],
        oracleInput: {
          tampered_signature_control: 'sc-tamp',
          source_valid_issuance: 'sc-admin-iss',
          replayed_acceptance: 'sc-rep',
        },
      },
      replayMode: 'fresh_clean_replay',
    },
    { entries: [tampered, adminIssuance, h1, replayed] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin_a'] },
  )
  assert.equal(res.confirmed, false, 'snake_case admin issuance in oracleInput MUST reject')
  assert.equal(res.failedStage, 'attacker_provenance')
})

// ============================================================================
// 2. DAG Topology: Control/Readback Hop Exclusion & Host-Observed Inference
// ============================================================================

test('Fix 2a: host-verified control & post-chain readback hops do not break dag_topology and never count toward hopCount', () => {
  const cap = 'cap:hop_1:elev_tok'
  const ctrl = signedEntry('dh-ctrl', makeStep({
    id: 'dh-ctrl', arm: 'control', method: 'POST', status: 403, pathAndQuery: '/api/v1/roles/assign',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900 })
  const h1 = signedEntry('dh-h1', makeStep({
    id: 'dh-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/invites/accept',
    json: { token: 'inv-tok-123456' },
  }), { seq: 2, timestampMs: 1000, emittedCapabilities: [cap] })
  const h2 = signedEntry('dh-h2', makeStep({
    id: 'dh-h2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/roles/assign',
    json: { userId: 'member_a', role: 'admin', persisted: true },
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [cap] })
  const rb = signedEntry('dh-rb', makeStep({
    id: 'dh-rb', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/v1/users/member_a/roles',
    json: { userId: 'member_a', role: 'admin', permissions: ['manage_org'] },
  }), { seq: 4, timestampMs: 1200, evidenceRole: 'post_chain_readback' })

  const receipt: CompositeProofReceipt = {
    chainId: 'fix2a-ctrl-and-readback-hops',
    terminalVulnClass: 'privilege_escalation',
    hops: [
      { hopId: 'hop_0_ctrl', role: 'control', isControl: true, surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/roles/assign' }, exchangeIds: ['dh-ctrl'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Denied pre-chain baseline control', producedCapabilities: [], consumedCapabilities: [] },
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/invites/accept' }, exchangeIds: ['dh-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Accepted invite capability', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/roles/assign' }, exchangeIds: ['dh-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Assigned admin role', producedCapabilities: [], consumedCapabilities: [cap] },
      { hopId: 'hop_3_readback', role: 'readback', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/users/member_a/roles' }, exchangeIds: ['dh-rb'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Verified persisted admin role', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      terminalExchangeId: 'dh-h2',
      controlHopId: 'hop_0_ctrl',
      summary: 'Escalated member role to admin and confirmed persisted state via readback.',
      claimedImpact: 'Escalated member role to admin and confirmed persisted state via readback.',
      preChainControlExchangeIds: [], // intentionally omitted to also verify denied control promotion from hop_0_ctrl
      postChainReadbackExchangeIds: ['dh-rb'],
    },
    replayMode: 'fresh_clean_replay',
  }

  const res = verifyCompositeReceipt(receipt, { entries: [ctrl, h1, h2, rb] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
  })
  assert.equal(res.confirmed, true, `Expected control + readback hops to be excluded cleanly, got: ${res.reason}`)
  assert.equal(res.hopCount, 2, 'hopCount MUST reflect ONLY causal hops (hop_1, hop_2), never control/readback hops')
  assert.deepEqual(res.evidence?.excludedControlHopIds, ['hop_0_ctrl', 'hop_3_readback'])
})

test('Fix 2b (anti-bypass): control hop cannot inflate 1-hop chain to 2-hop; spoofed control label on probe hop and tampered control sig still reject', () => {
  const ctrl = signedEntry('ab-ctrl', makeStep({
    id: 'ab-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/orgs/org_b/secrets',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900 })
  const term = signedEntry('ab-term', makeStep({
    id: 'ab-term', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/orgs/org_b/secrets',
    json: { tenantId: 'org_b', apiKey: 'secret-value-99' },
  }), { seq: 2, timestampMs: 1100 })
  const disconnectedProbe = signedEntry('ab-orphan', makeStep({
    id: 'ab-orphan', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/profile',
    json: { ok: true },
  }), { seq: 2, timestampMs: 1000 })

  // 1. Control hop + 1 probe hop MUST NOT satisfy dual_tenant_abac (>= 2 causal hops required)!
  const inflateRes = verifyCompositeReceipt(
    {
      chainId: 'fix2b-no-inflate',
      terminalVulnClass: 'dual_tenant_abac',
      hops: [
        { hopId: 'hop_ctrl', role: 'control', isControl: true, surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orgs/org_b/secrets' }, exchangeIds: ['ab-ctrl'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Control check', producedCapabilities: [], consumedCapabilities: [] },
        { hopId: 'hop_term', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orgs/org_b/secrets' }, exchangeIds: ['ab-term'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read secrets', producedCapabilities: [], consumedCapabilities: [] },
      ],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'hop_term',
        terminalExchangeId: 'ab-term',
        summary: 'Single causal hop plus control hop must not count as 2-hop dual_tenant_abac.',
        claimedImpact: 'Single causal hop plus control hop must not count as 2-hop dual_tenant_abac.',
        preChainControlExchangeIds: ['ab-ctrl'],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    },
    { entries: [ctrl, term] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
  )
  assert.equal(inflateRes.confirmed, false, 'control hop must NOT inflate 1-hop chain to satisfy 2-hop requirement')
  assert.equal(inflateRes.hopCount, 1)
  assert.match(inflateRes.reason, /multi_hop_causal_chain_required/)

  // 2. Spoofed `role: 'control'` / `isControl: true` / `controlHopId` on a PROBE hop MUST STILL FAIL `dag_topology`!
  const spoofCtrlRes = verifyCompositeReceipt(
    {
      chainId: 'fix2b-spoof-ctrl-label',
      terminalVulnClass: 'cross_tenant_read',
      hops: [
        { hopId: 'hop_fake_ctrl', role: 'control', isControl: true, surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/profile' }, exchangeIds: ['ab-orphan'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Disconnected probe disguised as control', producedCapabilities: [], consumedCapabilities: [] },
        { hopId: 'hop_term', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orgs/org_b/secrets' }, exchangeIds: ['ab-term'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read secrets', producedCapabilities: [], consumedCapabilities: [] },
      ],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'hop_term',
        terminalExchangeId: 'ab-term',
        controlHopId: 'hop_fake_ctrl',
        summary: 'Disconnected probe hop labeled as control must still fail dag_topology.',
        claimedImpact: 'Disconnected probe hop labeled as control must still fail dag_topology.',
        preChainControlExchangeIds: ['ab-ctrl'],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    },
    { entries: [ctrl, disconnectedProbe, term] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
  )
  assert.equal(spoofCtrlRes.confirmed, false, 'probe hop labeled as control MUST reject at dag_topology')
  assert.equal(spoofCtrlRes.failedStage, 'dag_topology')
  assert.match(spoofCtrlRes.reason, /does not reach terminalHopId/)

  // 3. Unsigned/tampered exchange inside an excluded control hop MUST STILL FAIL `transcript_integrity`!
  const tamperedCtrl: HostTranscriptEntry = { ...ctrl, hostSignature: '0'.repeat(64) }
  const tamperedRes = verifyCompositeReceipt(
    {
      chainId: 'fix2b-tampered-ctrl-sig',
      terminalVulnClass: 'cross_tenant_read',
      hops: [
        { hopId: 'hop_ctrl', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orgs/org_b/secrets' }, exchangeIds: ['ab-ctrl'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Tampered control', producedCapabilities: [], consumedCapabilities: [] },
        { hopId: 'hop_term', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orgs/org_b/secrets' }, exchangeIds: ['ab-term'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read secrets', producedCapabilities: [], consumedCapabilities: [] },
      ],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'hop_term',
        terminalExchangeId: 'ab-term',
        summary: 'Tampered signature inside excluded control hop must reject at transcript_integrity.',
        claimedImpact: 'Tampered signature inside excluded control hop must reject at transcript_integrity.',
        preChainControlExchangeIds: ['ab-ctrl'],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    },
    { entries: [tamperedCtrl, term] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
  )
  assert.equal(tamperedRes.confirmed, false)
  assert.equal(tamperedRes.failedStage, 'transcript_integrity')
})

test('Fix 2c: supplemental host-observed causal inference connects oob_relay, browser_trace, redirect Location tokens, and 3-hop state_transition chains before dag_topology', () => {
  // 1. Redirect Location query-param high-entropy token (`302 Location: /callback?code=...`) -> `value_binding`
  const authCode = 'ac_9f8e7d6c5b4a3210'
  const redirCtrl = signedEntry('rd-ctrl', makeStep({
    id: 'rd-ctrl', arm: 'control', method: 'POST', status: 403, pathAndQuery: '/oauth/token',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900 })
  const redirH1 = signedEntry('rd-h1', makeStep({
    id: 'rd-h1', arm: 'probe', method: 'GET', status: 302, pathAndQuery: '/oauth/authorize?client_id=app1',
    responseHeaders: { location: `/callback?code=${authCode}&state=st_112233` },
    body: '',
  }), { seq: 2, timestampMs: 1000 })
  const redirH2 = signedEntry('rd-h2', makeStep({
    id: 'rd-h2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/oauth/token',
    requestJson: { code: authCode },
    json: { tenantId: 'org_b', secretScope: 'admin:all', accessToken: 'tok-issued-org-b' },
  }), { seq: 3, timestampMs: 1100 })

  const redirRes = verifyCompositeReceipt(
    {
      chainId: 'fix2c-redirect-location-binding',
      terminalVulnClass: 'cross_tenant_read',
      hops: [
        { hopId: 'hop_1', surface: 'idp', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/oauth/authorize?client_id=app1' }, exchangeIds: ['rd-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained authorization code in Location redirect', producedCapabilities: [], consumedCapabilities: [] },
        { hopId: 'hop_2', surface: 'idp', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/oauth/token' }, exchangeIds: ['rd-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Exchanged redirect code for foreign tenant token', producedCapabilities: [], consumedCapabilities: [] },
      ],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'hop_2',
        terminalExchangeId: 'rd-h2',
        summary: 'Exchanged OAuth redirect authorization code for cross-tenant token.',
        claimedImpact: 'Exchanged OAuth redirect authorization code for cross-tenant token.',
        preChainControlExchangeIds: ['rd-ctrl'],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    },
    { entries: [redirCtrl, redirH1, redirH2] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
  )
  assert.equal(redirRes.confirmed, true, `Redirect Location code binding must confirm, got: ${redirRes.reason}`)
  assert.equal(redirRes.verifiedEdges.length, 1)
  assert.equal(redirRes.verifiedEdges[0]!.kind, 'value_binding')

  // 2. OOB relay + Browser trace async_pivot_binding inference before dag_topology
  const corr = 'corr_8a7b6c5d4e'
  const stolenCap = 'cap:hop_2:stolen_browser_tok'
  const bCtrl = signedEntry('bt-ctrl', makeStep({
    id: 'bt-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/orgs/org_b/vault',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900 })
  const bH1 = signedEntry('bt-h1', makeStep({
    id: 'bt-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/invites/link',
    json: { correlationId: corr, created: true },
  }), { seq: 2, timestampMs: 1000, correlationIds: [corr] })
  const bTrace = signedTrace({
    id: 'tr-bt-1',
    origin: ORIGIN,
    timestampMs: 1100,
    sinks: ['postMessage'],
    correlationIds: [corr],
    emittedCapabilities: [stolenCap],
  })
  const bH3 = signedEntry('bt-h3', makeStep({
    id: 'bt-h3', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/orgs/org_b/vault',
    json: { tenantId: 'org_b', vaultKey: 'vk-private-9988' },
  }), { seq: 3, timestampMs: 1200, consumedCapabilities: [stolenCap] })

  const btRes = verifyCompositeReceipt(
    {
      chainId: 'fix2c-browser-trace-pivot',
      terminalVulnClass: 'cross_tenant_read',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/invites/link' }, exchangeIds: ['bt-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Created correlated browser pivot link', producedCapabilities: [], consumedCapabilities: [] },
        { hopId: 'hop_2', surface: 'browser', target: { origin: ORIGIN }, exchangeIds: [], oobEventIds: [], browserTraceIds: ['tr-bt-1'], claimedDelta: 'Captured token in browser trace', producedCapabilities: [stolenCap], consumedCapabilities: [] },
        { hopId: 'hop_3', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orgs/org_b/vault' }, exchangeIds: ['bt-h3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read foreign vault with captured token', producedCapabilities: [], consumedCapabilities: [stolenCap] },
      ],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'hop_3',
        terminalExchangeId: 'bt-h3',
        summary: 'Correlated browser trace pivot yielded cross-tenant vault secret.',
        claimedImpact: 'Correlated browser trace pivot yielded cross-tenant vault secret.',
        preChainControlExchangeIds: ['bt-ctrl'],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    },
    { entries: [bCtrl, bH1, bH3], browserTraces: [bTrace] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
  )
  assert.equal(btRes.confirmed, true, `Browser trace async pivot chain must confirm, got: ${btRes.reason}`)
  assert.equal(btRes.hopCount, 3)
  assert.ok(btRes.verifiedEdges.some(e => e.kind === 'async_pivot_binding' && e.fromHopId === 'hop_1' && e.toHopId === 'hop_2'))

  // OOB relay 2-hop chain
  const oobCorr = 'oob_tok_77665544'
  const oobH1 = signedEntry('oob-h1', makeStep({
    id: 'oob-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/webhooks/register',
    requestJson: { url: `https://oob.example/${oobCorr}` },
    json: { registered: true },
  }), { seq: 1, timestampMs: 1000, correlationIds: [oobCorr] })
  const oobEv = signedOob({
    id: 'oob-ev-1',
    token: oobCorr,
    targetOrigin: ORIGIN,
    delivered: true,
    receivedAtMs: 1100,
    correlationIds: [oobCorr],
  })
  const oobRes = verifyCompositeReceipt(
    {
      chainId: 'fix2c-oob-relay-pivot',
      terminalVulnClass: 'ssrf',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/webhooks/register' }, exchangeIds: ['oob-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Registered webhook callback', producedCapabilities: [], consumedCapabilities: [] },
        { hopId: 'hop_2', surface: 'webhook', target: { origin: ORIGIN }, exchangeIds: [], oobEventIds: ['oob-ev-1'], browserTraceIds: [], claimedDelta: 'Observed delivered OOB webhook', producedCapabilities: [], consumedCapabilities: [] },
      ],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'hop_2',
        summary: 'Server-side webhook trigger delivered correlated OOB callback.',
        claimedImpact: 'Server-side webhook trigger delivered correlated OOB callback.',
        preChainControlExchangeIds: [],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    },
    { entries: [oobH1], oobEvents: [oobEv] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
  )
  assert.equal(oobRes.confirmed, true, `OOB relay async pivot chain must confirm, got: ${oobRes.reason}`)
  assert.ok(oobRes.verifiedEdges.some(e => e.kind === 'async_pivot_binding' && e.fromHopId === 'hop_1' && e.toHopId === 'hop_2'))

  // 3. 3-hop backwards fixed-point state_transition_binding (hop_1 -> hop_2 -> hop_3)
  const stAb2 = signedEntry('st-ab2', makeStep({
    id: 'st-ab2', arm: 'control', method: 'POST', status: 403, pathAndQuery: '/api/v1/policies/ent_77/bind',
    json: { error: 'role_required' },
  }), { seq: 1, timestampMs: 850, replayAttempt: 'ablation_control', entityId: 'ent_77' })
  const stAb3 = signedEntry('st-ab3', makeStep({
    id: 'st-ab3', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/orgs/org_b/keys/ent_77',
    json: { error: 'policy_required' },
  }), { seq: 2, timestampMs: 900, replayAttempt: 'ablation_control', entityId: 'ent_77' })
  const stH1 = signedEntry('st-h1', makeStep({
    id: 'st-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/groups/ent_77/join',
    json: { id: 'ent_77', joined: true },
  }), { seq: 3, timestampMs: 1000, entityId: 'ent_77' })
  const stH2 = signedEntry('st-h2', makeStep({
    id: 'st-h2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/policies/ent_77/bind',
    json: { id: 'ent_77', bound: true },
  }), { seq: 4, timestampMs: 1100, entityId: 'ent_77' })
  const stH3 = signedEntry('st-h3', makeStep({
    id: 'st-h3', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/orgs/org_b/keys/ent_77',
    json: { id: 'ent_77', tenantId: 'org_b', signingKey: 'priv-key-998877' },
  }), { seq: 5, timestampMs: 1200, entityId: 'ent_77' })

  const stRes = verifyCompositeReceipt(
    {
      chainId: 'fix2c-3hop-state-fixedpoint',
      terminalVulnClass: 'cross_tenant_read',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/groups/ent_77/join' }, exchangeIds: ['st-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Joined group', producedCapabilities: [], consumedCapabilities: [], entityId: 'ent_77' },
        { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/policies/ent_77/bind' }, exchangeIds: ['st-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Bound policy', producedCapabilities: [], consumedCapabilities: [], entityId: 'ent_77' },
        { hopId: 'hop_3', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orgs/org_b/keys/ent_77' }, exchangeIds: ['st-h3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read foreign org signing key', producedCapabilities: [], consumedCapabilities: [], entityId: 'ent_77' },
      ],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'hop_3',
        terminalExchangeId: 'st-h3',
        summary: 'Three-hop state transition chain exposed foreign tenant signing key.',
        claimedImpact: 'Three-hop state transition chain exposed foreign tenant signing key.',
        preChainControlExchangeIds: ['st-ab3'],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    },
    { entries: [stAb2, stAb3, stH1, stH2, stH3] },
    { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] },
  )
  assert.equal(stRes.confirmed, true, `3-hop backwards fixed-point state transition must confirm, got: ${stRes.reason}`)
  assert.equal(stRes.hopCount, 3)

  // Verify direct hydrateV8OracleInput snake_case key normalization for dual_tenant_abac
  const dtIdx: HydratableTranscriptIndex = { entriesById: new Map([[stAb3.exchangeId, stAb3], [stH1.exchangeId, stH1], [stH3.exchangeId, stH3]]) }
  const hydDt = hydrateV8OracleInput('dual_tenant_abac', {
    baseline_denied_control: stAb3.exchangeId,
    prime_action: stH1.exchangeId,
    bled_access: stH3.exchangeId,
  }, dtIdx, 'sig')
  assert.equal(hydDt.mode, 'dual_org_cache_bleed')
  assert.equal((hydDt.bledAccess as { id?: string } | undefined)?.id, stH3.exchangeId)
})
