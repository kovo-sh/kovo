/**
 * Move 1 (Host-Side Causal Proof Compiler Foundation) + Grey-Box Precision & Recall P0 Tests.
 *
 * Verifies all 4 systemic kernel requirements end-to-end:
 *   1. Close BOTH grey-box decoy FP classes:
 *      (a) Reject read-only directory/roster/metadata GET as `privilege_escalation`/`bfla`
 *      (b) Positive non-reflected `hasForeignTenantData` on `CROSS_TENANT_CLASS_RE` (strips request URL/query tokens from CSV & JSON)
 *      (c) Reject bogus `GET -> GET` `state_transition_binding`
 *      (d) Never silently drop `terminalImpact.oracleInput` when `oracleFamily` is omitted
 *   2. Mode-A normalized terminal endpoint agreement across fresh per-run entity IDs
 *   3. Host-side backwards causal proof compiler (`compileCausalChainFromTranscript`) + ancestor-cap `AutoDag` rewire
 *   4. Single-attempt fast-fail on `checkpoint` / `execution` + actionable Mode-A guidance & non-secret HTTP shape summary
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import test from 'node:test'
import {
  compileCausalChainFromTranscript,
  inferV8OracleFamilyFromInput,
  normalizeCompositeTerminalEndpoint,
} from '../src/server/causal-proof-compiler.ts'
import {
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { runAgentScriptProof } from '../src/server/agent-script-proof.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import { TranscriptStore } from '../src/server/verify-claims.ts'
import { verifyScript, type VerifyAttemptSession } from '../src/server/verify-runner.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'

const SIGNING_KEY = 'm2-move1-gb-kernel-signing-key-2026'
const ORIGIN = 'http://127.0.0.1:4120'
process.env.KOVO_ALLOW_LOCAL_LAB = '1'

function makeStep(partial: Partial<ImpactStep> & { id: string; arm: ImpactStep['arm']; method: string; status: number }): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    route: partial.route ?? (partial.pathAndQuery?.split('?')[0] ?? '/api/v1/resource'),
    pathAndQuery: partial.pathAndQuery ?? partial.route ?? '/api/v1/resource',
    status: partial.status,
    actor: partial.actor ?? { handle: 'member_a', role: 'member', tenant: 'org_a', auth: 'bearer', sameSite: null },
    ...(partial.json !== undefined ? { json: partial.json } : {}),
    ...(partial.body !== undefined ? { body: partial.body } : {}),
    ...(partial.requestJson !== undefined ? { requestJson: partial.requestJson } : {}),
    ...(partial.requestHeaders ? { requestHeaders: partial.requestHeaders } : {}),
    ...(partial.responseHeaders ? { responseHeaders: partial.responseHeaders } : {}),
  }
}

function signedEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry> = {},
): HostTranscriptEntry {
  const base: HostTranscriptEntry = {
    exchangeId,
    origin: ORIGIN,
    timestampMs: 1_700_000_000_000,
    actorPersona: step.actor.handle,
    actorRoleLabel: step.actor.role && step.actor.tenant ? `${step.actor.role} (${step.actor.tenant})` : null,
    cleanSession: true,
    step,
    ...extra,
  }
  return { ...base, hostSignature: signHostRecord(base, SIGNING_KEY) }
}

// ============================================================================
// Requirement 1: Close BOTH Grey-Box Decoy FP Classes (1a, 1b, 1c, 1d)
// ============================================================================

test('Req 1(a): rejects read-only directory/roster/metadata GET as privilege_escalation/bfla; confirms mutating + readback', () => {
  const inviteCap = 'cap:hop_1:invite_tok_1a'
  const h1 = signedEntry('ex-1a-h1', makeStep({
    id: 'ex-1a-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/v1/invites/resolve',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { token: 'inv-tok-1' },
  }), { seq: 1, timestampMs: 1000, emittedCapabilities: [inviteCap] })

  const ctrl = signedEntry('ex-1a-ctrl', makeStep({
    id: 'ex-1a-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/v1/orgs/org_a/members',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { error: 'forbidden' },
  }), { seq: 2, timestampMs: 1050 })

  const h2Roster = signedEntry('ex-1a-h2', makeStep({
    id: 'ex-1a-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/orgs/org_a/members',
    actor: { handle: inviteCap, role: null, tenant: null, auth: 'bearer', sameSite: null },
    json: { members: [{ id: 'u1', email: 'owner@org-a.example', role: 'owner' }] },
  }), { seq: 3, timestampMs: 1100, actorPersona: inviteCap, actorRoleLabel: null, consumedCapabilities: [inviteCap] })

  for (const vulnClass of ['privilege_escalation', 'bfla'] as const) {
    const receipt: CompositeProofReceipt = {
      chainId: `gb-1a-roster-${vulnClass}`,
      terminalVulnClass: vulnClass,
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/invites/resolve' }, exchangeIds: ['ex-1a-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Resolved invite token', producedCapabilities: [inviteCap], consumedCapabilities: [] },
        { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/orgs/org_a/members' }, exchangeIds: ['ex-1a-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Listed org members roster', producedCapabilities: [], consumedCapabilities: [inviteCap] },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: inviteCap }],
      terminalImpact: {
        terminalHopId: 'hop_2',
        terminalExchangeId: 'ex-1a-h2',
        summary: 'Read-only member roster GET claimed as escalation.',
        claimedImpact: 'Read-only member roster GET claimed as escalation.',
        preChainControlExchangeIds: ['ex-1a-ctrl'],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    }
    const res = verifyCompositeReceipt(receipt, { entries: [h1, ctrl, h2Roster] }, {
      signingKey: SIGNING_KEY, attackerPersonas: ['member_b'],
    })
    assert.equal(res.confirmed, false, `${vulnClass} on read-only roster GET must reject`)
    assert.equal(res.failedStage, 'terminal_impact')
    assert.equal(res.rejectedBy, 'terminal_impact_unproven')
  }

  // Positive control: state-mutating terminal action + postMutRb STILL confirms cleanly!
  const mutCtrl = signedEntry('ex-1a-mut-ctrl', makeStep({
    id: 'ex-1a-mut-ctrl', arm: 'control', method: 'POST', status: 403, pathAndQuery: '/v1/payouts/pay_99/approve',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { error: 'forbidden' },
  }), { seq: 2, timestampMs: 1050 })
  const mutProbe = signedEntry('ex-1a-mut', makeStep({
    id: 'ex-1a-mut', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/v1/payouts/pay_99/approve',
    actor: { handle: inviteCap, role: null, tenant: null, auth: 'bearer', sameSite: null },
    json: { id: 'pay_99', status: 'approved', amountCents: 250000 },
  }), { seq: 3, timestampMs: 1100, actorPersona: inviteCap, actorRoleLabel: null, consumedCapabilities: [inviteCap] })
  const mutRb = signedEntry('ex-1a-rb', makeStep({
    id: 'ex-1a-rb', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/v1/payouts/pay_99',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { id: 'pay_99', status: 'approved', amountCents: 250000 },
  }), { seq: 4, timestampMs: 1200, evidenceRole: 'post_chain_readback' })

  const mutReceipt: CompositeProofReceipt = {
    chainId: 'gb-1a-mut-ok',
    terminalVulnClass: 'privilege_escalation',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/invites/resolve' }, exchangeIds: ['ex-1a-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Resolved invite token', producedCapabilities: [inviteCap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/payouts/pay_99/approve' }, exchangeIds: ['ex-1a-mut'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Approved payout via escalated invite token', producedCapabilities: [], consumedCapabilities: [inviteCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: inviteCap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      terminalExchangeId: 'ex-1a-mut',
      summary: 'Privileged payout approval persisted and verified via readback.',
      claimedImpact: 'Privileged payout approval persisted and verified via readback.',
      preChainControlExchangeIds: ['ex-1a-mut-ctrl'],
      postChainReadbackExchangeIds: ['ex-1a-rb'],
    },
    replayMode: 'fresh_clean_replay',
  }
  const mutRes = verifyCompositeReceipt(mutReceipt, { entries: [h1, mutCtrl, mutProbe, mutRb] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_b'],
  })
  assert.equal(mutRes.confirmed, true, `mutating privilege_escalation + readback must confirm, got: ${mutRes.reason}`)
})

test('Req 1(b) & 1(c): rejects reflected CSV/JSON tenant slug and bogus GET->GET state_transition_binding; confirms genuine foreign-tenant JSON', () => {
  const sigCap = 'cap:hop_1:export_sig_1b'
  const actorA = { handle: 'member_a', role: 'member' as const, tenant: 'acme', auth: 'bearer' as const, sameSite: null }
  const h1 = signedEntry('ex-1b-h1', makeStep({
    id: 'ex-1b-h1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/exports/job_36/url',
    actor: actorA, json: { signedUrl: '/files/export/acme/treasury-acme.csv?job=job_36&tenant=acme&sig=s1' },
  }), { seq: 1, timestampMs: 1000, emittedCapabilities: [sigCap], entityId: 'job_36' })
  const h2 = signedEntry('ex-1b-h2', makeStep({
    id: 'ex-1b-h2', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: `/files/export/acme/treasury-acme.csv?job=job_36&tenant=acme&sig=${sigCap}`,
    actor: actorA, responseHeaders: { 'content-type': 'text/csv; charset=utf-8' },
    body: 'field,value\ntenant,acme\nbalance_cents,50000\n',
  }), { seq: 2, timestampMs: 1100, consumedCapabilities: [sigCap], entityId: 'job_36' })
  const ablCtrl = signedEntry('ex-1b-ctrl', makeStep({
    id: 'ex-1b-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/files/export/acme-labs/treasury-acme.csv?job=job_36&tenant=acme&sig=invalid',
    actor: actorA, json: { error: 'invalid_signature' },
  }), { seq: 3, timestampMs: 1150, replayAttempt: 'ablation_control', entityId: 'job_36' })
  const h3Csv = signedEntry('ex-1b-h3', makeStep({
    id: 'ex-1b-h3', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: `/files/export/acme-labs/treasury-acme.csv?job=job_36&tenant=acme&sig=${sigCap}`,
    actor: actorA, responseHeaders: { 'content-type': 'text/csv; charset=utf-8' },
    body: 'field,value\ntenant,acme-labs\nbalance_cents,50000\n',
  }), { seq: 4, timestampMs: 1200, consumedCapabilities: [sigCap], entityId: 'job_36' })

  // 1(c): GET -> GET state_transition_binding MUST reject at edge_binding!
  const getGetReceipt: CompositeProofReceipt = {
    chainId: 'gb-1c-get-get',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/exports/job_36/url' }, exchangeIds: ['ex-1b-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Minted signed URL', producedCapabilities: [sigCap], consumedCapabilities: [], entityId: 'job_36' },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/files/export/acme/treasury-acme.csv?job=job_36&tenant=acme&sig=${sigCap}` }, exchangeIds: ['ex-1b-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Fetched own CSV', producedCapabilities: [], consumedCapabilities: [sigCap], entityId: 'job_36' },
      { hopId: 'hop_3', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/files/export/acme-labs/treasury-acme.csv?job=job_36&tenant=acme&sig=${sigCap}` }, exchangeIds: ['ex-1b-h3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Reflected path slug in CSV', producedCapabilities: [], consumedCapabilities: [sigCap], entityId: 'job_36' },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: sigCap },
      { kind: 'state_transition_binding', fromHopId: 'hop_2', toHopId: 'hop_3', entityId: 'job_36', ablationExchangeIds: ['ex-1b-ctrl'] },
    ],
    terminalImpact: {
      terminalHopId: 'hop_3',
      terminalExchangeId: 'ex-1b-h3',
      summary: 'Reflected path slug in CSV with GET->GET state transition.',
      claimedImpact: 'Reflected path slug in CSV with GET->GET state transition.',
      preChainControlExchangeIds: ['ex-1b-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const rGetGet = verifyCompositeReceipt(getGetReceipt, { entries: [h1, h2, ablCtrl, h3Csv] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
  })
  assert.equal(rGetGet.confirmed, false, 'GET->GET state_transition_binding must reject')
  assert.equal(rGetGet.failedStage, 'edge_binding')
  assert.match(rGetGet.reason, /state-mutating fromHop/i)

  // 1(b): Even with valid value_binding (no GET->GET edge), reflected path slug in CSV MUST reject at terminal_impact!
  const reflectedCsvReceipt: CompositeProofReceipt = {
    ...getGetReceipt,
    chainId: 'gb-1b-reflected-csv',
    hops: [getGetReceipt.hops[0]!, getGetReceipt.hops[2]!],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_3', capabilityHandle: sigCap }],
  }
  const rCsv = verifyCompositeReceipt(reflectedCsvReceipt, { entries: [h1, ablCtrl, h3Csv] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
  })
  assert.equal(rCsv.confirmed, false, 'Reflected path slug in text/csv must not confirm cross_tenant_read')
  assert.equal(rCsv.failedStage, 'terminal_impact')
  assert.equal(rCsv.rejectedBy, 'terminal_impact_unproven')

  // 1(b) JSON reflected query param MUST also reject!
  const h3JsonReflected = signedEntry('ex-1b-json-ref', makeStep({
    id: 'ex-1b-json-ref', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: `/v1/exports/download?tenant=victim_co&sig=${sigCap}`,
    actor: actorA, json: { tenant: 'victim_co', rows: [{ id: '1', total: 100 }] },
  }), { seq: 4, timestampMs: 1200, consumedCapabilities: [sigCap] })
  const ctrlJsonRef = signedEntry('ex-1b-json-ctrl', makeStep({
    id: 'ex-1b-json-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/v1/exports/download?tenant=victim_co&sig=invalid',
    actor: actorA, json: { error: 'forbidden' },
  }), { seq: 3, timestampMs: 1150 })
  const reflectedJsonReceipt: CompositeProofReceipt = {
    chainId: 'gb-1b-reflected-json',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      getGetReceipt.hops[0]!,
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/v1/exports/download?tenant=victim_co&sig=${sigCap}` }, exchangeIds: ['ex-1b-json-ref'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Reflected query tenant in JSON', producedCapabilities: [], consumedCapabilities: [sigCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: sigCap }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'ex-1b-json-ref',
      summary: 'Reflected query tenant in JSON response.', claimedImpact: 'Reflected query tenant in JSON response.',
      preChainControlExchangeIds: ['ex-1b-json-ctrl'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const rJsonRef = verifyCompositeReceipt(reflectedJsonReceipt, { entries: [h1, ctrlJsonRef, h3JsonReflected] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
  })
  assert.equal(rJsonRef.confirmed, false, 'Reflected query tenant in JSON must not confirm cross_tenant_read')
  assert.equal(rJsonRef.failedStage, 'terminal_impact')

  // 1(b) Positive control: non-reflected foreign tenant in JSON confirms cleanly!
  const h3Genuine = signedEntry('ex-1b-gen', makeStep({
    id: 'ex-1b-gen', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: `/v1/exports/job_36/download?sig=${sigCap}`,
    actor: actorA, json: { tenantId: 'other_corp', rows: [{ id: 'r1', balanceCents: 99000 }] },
  }), { seq: 4, timestampMs: 1200, consumedCapabilities: [sigCap] })
  const ctrlGen = signedEntry('ex-1b-gen-ctrl', makeStep({
    id: 'ex-1b-gen-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/v1/exports/job_36/download?sig=invalid',
    actor: actorA, json: { error: 'forbidden' },
  }), { seq: 3, timestampMs: 1150 })
  const genuineReceipt: CompositeProofReceipt = {
    ...reflectedJsonReceipt,
    chainId: 'gb-1b-genuine-foreign',
    hops: [
      getGetReceipt.hops[0]!,
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/v1/exports/job_36/download?sig=${sigCap}` }, exchangeIds: ['ex-1b-gen'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read foreign tenant export', producedCapabilities: [], consumedCapabilities: [sigCap] },
    ],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'ex-1b-gen',
      summary: 'Read non-reflected foreign tenant export data.', claimedImpact: 'Read non-reflected foreign tenant export data.',
      preChainControlExchangeIds: ['ex-1b-gen-ctrl'], postChainReadbackExchangeIds: [],
    },
  }
  const rGen = verifyCompositeReceipt(genuineReceipt, { entries: [h1, ctrlGen, h3Genuine] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
  })
  assert.equal(rGen.confirmed, true, `Genuine non-reflected foreign tenant must confirm, got: ${rGen.reason}`)
})

test('Req 1(d): never silently drops terminalImpact.oracleInput when oracleFamily is omitted', () => {
  assert.equal(inferV8OracleFamilyFromInput({ tamperedSignatureControl: 'c1', replayedAcceptance: 'r1' }), 'cryptographic_scope_replay')
  assert.equal(inferV8OracleFamilyFromInput({ mode: 'dual_org_cache_bleed', bledAccess: 'b1' }), 'dual_tenant_abac')
  assert.equal(inferV8OracleFamilyFromInput({ equation: 'over_refund', beforeBalance: 100 }), 'economic_conservation')
  assert.equal(inferV8OracleFamilyFromInput({ unknownArbitraryKey: 'foo' }), null)

  const cap = 'cap:hop_1:tok_1d'
  const h1 = signedEntry('ex-1d-h1', makeStep({
    id: 'ex-1d-h1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/exports/j1/url',
    json: { token: 'sig-1' },
  }), { seq: 1, timestampMs: 1000, emittedCapabilities: [cap] })
  const ctrl = signedEntry('ex-1d-ctrl', makeStep({
    id: 'ex-1d-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/v1/exports/j1/data',
    json: { error: 'forbidden' },
  }), { seq: 2, timestampMs: 1050 })
  const h2 = signedEntry('ex-1d-h2', makeStep({
    id: 'ex-1d-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/exports/j1/data',
    json: { tenantId: 'org_b', rows: [{ id: '1', total: 500 }] },
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [cap] })

  // Unmapped oracleInput without oracleFamily -> MUST fail closed (NOT silently ignored!)
  const unmappedReceipt: CompositeProofReceipt = {
    chainId: 'gb-1d-unmapped',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/exports/j1/url' }, exchangeIds: ['ex-1d-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained link', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/exports/j1/data' }, exchangeIds: ['ex-1d-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read data', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'ex-1d-h2',
      summary: 'Supplied unmapped oracleInput without oracleFamily.', claimedImpact: 'Supplied unmapped oracleInput without oracleFamily.',
      preChainControlExchangeIds: ['ex-1d-ctrl'], postChainReadbackExchangeIds: [],
      oracleInput: { spoofedHint: 'not-a-valid-v8-schema' },
    },
    replayMode: 'fresh_clean_replay',
  }
  const rUnmapped = verifyCompositeReceipt(unmappedReceipt, { entries: [h1, ctrl, h2] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
  })
  assert.equal(rUnmapped.confirmed, false, 'Unmapped oracleInput without oracleFamily must fail closed')
  assert.equal(rUnmapped.failedStage, 'terminal_impact')
  assert.equal(rUnmapped.rejectedBy, 'v8_oracle_family_missing')

  // Recognizable v8 oracleInput (cryptographic_scope_replay) without oracleFamily -> dispatches strict v8 oracle (and fails closed if invalid!)
  const inferredReceipt: CompositeProofReceipt = {
    ...unmappedReceipt,
    chainId: 'gb-1d-inferred',
    terminalImpact: {
      ...unmappedReceipt.terminalImpact,
      oracleInput: { tamperedSignatureControl: 'ex-1d-ctrl', sourceValidIssuance: 'ex-1d-h2', replayedAcceptance: 'ex-1d-h2' },
    },
  }
  const rInferred = verifyCompositeReceipt(inferredReceipt, { entries: [h1, ctrl, h2] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
  })
  assert.equal(rInferred.confirmed, false, 'Inferred cryptographic_scope_replay with same issuance/replay must fail closed')
  assert.equal(rInferred.rejectedBy, 'v8_oracle_cryptographic_scope_replay')
})

// ============================================================================
// Requirement 2: Mode-A Agreement Normalization Across Fresh Entity IDs
// ============================================================================

test('Req 2: Mode-A terminal endpoint normalization agrees on fresh per-run entity IDs and rejects distinct routes', async t => {
  assert.equal(
    normalizeCompositeTerminalEndpoint('/v1/orders/mh_ord_16_abc123/settle-race'),
    normalizeCompositeTerminalEndpoint('/v1/orders/mh_ord_17_def456/settle-race'),
  )
  assert.equal(
    normalizeCompositeTerminalEndpoint('/v1/payouts/pay_1001/approve?x=1'),
    normalizeCompositeTerminalEndpoint('/v1/payouts/pay_2002/approve?x=2'),
  )
  assert.notEqual(
    normalizeCompositeTerminalEndpoint('/v1/orders/mh_ord_16_abc123/settle-race'),
    normalizeCompositeTerminalEndpoint('/v1/payouts/mh_ord_16_abc123/approve'),
  )

  // End-to-end dual-attempt runAgentScriptProof over real loopback HTTP + RequestBroker where
  // Attempt 1 mints mh_ord_101_aaa and Attempt 2 mints mh_ord_202_bbb!
  let attemptCounter = 0
  const server = createServer((req, res) => {
    req.resume()
    const m = (req.method ?? 'GET').toUpperCase()
    const url = req.url ?? '/'
    res.setHeader('content-type', 'application/json')
    if (m === 'POST' && url === '/v1/orders') {
      const oid = attemptCounter === 1 ? 'mh_ord_101_aaa' : 'mh_ord_202_bbb'
      res.statusCode = 201
      res.end(JSON.stringify({ id: oid }))
      return
    }
    if (m === 'POST' && /\/settle-race$/.test(url)) {
      if (!req.headers['x-auth-cap']) {
        res.statusCode = 403
        res.end(JSON.stringify({ error: 'denied' }))
        return
      }
      res.statusCode = 200
      res.end(JSON.stringify({ settled: true, amountCents: 90000 }))
      return
    }
    res.statusCode = 404
    res.end('{}')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as { port: number }).port
  const liveOrigin = `http://127.0.0.1:${port}`
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(r => server.close(() => r()))
  })

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const grant = {
    canRead: () => true,
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map([
      ['member_a', { id: 'p1', handle: 'member_a', roleLabel: 'member (org_a)', originAllowlist: [liveOrigin], authKind: 'bearer', headerName: null, secret: 'tok-a-secret', canaryMarkers: [] }],
    ]),
  } as unknown as Grant

  const script = `
    const h1 = await ctx.http_send(${JSON.stringify(liveOrigin + '/v1/orders')}, { as: 'member_a', method: 'POST', role: 'probe' })
    const cap = await ctx.seal_capability({ exchangeId: h1.exchangeId, hopId: 'hop_1', slot: 'order_id', jsonPath: '$.id' })
    const settleUrl = ${JSON.stringify(liveOrigin + '/v1/orders/')} + h1.json.id + '/settle-race'
    const ctrl = await ctx.http_send(settleUrl, { as: 'member_a', method: 'POST', role: 'control', entityId: h1.json.id })
    const h2 = await ctx.http_send(settleUrl, { as: 'member_a', method: 'POST', role: 'probe', headers: { 'x-auth-cap': cap.handle }, entityId: h1.json.id })
    await ctx.prove_composite({
      chainId: 'modea-fresh-entity',
      terminalVulnClass: 'ledger_overcredit',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ${JSON.stringify(liveOrigin)}, method: 'POST', pathAndQuery: '/v1/orders' }, exchangeIds: [h1.exchangeId], claimedDelta: 'Created fresh order', producedCapabilities: [cap.handle], entityId: h1.json.id },
        { hopId: 'hop_2', surface: 'http', target: { origin: ${JSON.stringify(liveOrigin)}, method: 'POST', pathAndQuery: '/v1/orders/' + h1.json.id + '/settle-race' }, exchangeIds: [h2.exchangeId], claimedDelta: 'Settled fresh order', consumedCapabilities: [cap.handle], entityId: h1.json.id },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap.handle }],
      terminalImpact: {
        terminalHopId: 'hop_2',
        terminalExchangeId: h2.exchangeId,
        summary: 'Fresh per-run entity order settlement confirmed across both Mode-A attempts.',
        preChainControlExchangeIds: [ctrl.exchangeId],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    })
    return ctx.result({ title: 'Fresh entity Mode-A agreement' })
  `

  const { runCandidateLocally } = await import('../src/server/verify-runner.ts')
  const { join, resolve } = await import('node:path')
  const sdkDir = resolve(process.cwd(), 'worker', 'kovo_verify')

  const backend = {
    async openSession(_id: string, _signal: AbortSignal, opts?: { rpcMountDir?: string }) {
      attemptCounter += 1
      const rpcDir = opts?.rpcMountDir
      assert.ok(rpcDir, 'rpcMountDir required')
      return {
        async runCommand() { return { stdout: '', stderr: '', exitCode: 0, durationMs: 0 } },
        async verifyScript(req: { code: string; nonce: string }, signal: AbortSignal) {
          return runCandidateLocally(
            { name: 'modea.ts', runtime: 'ts', code: req.code },
            {
              socketPath: join(rpcDir, 'verify.sock'),
              tokenPath: join(rpcDir, 'token'),
              contextPath: join(rpcDir, 'context.json'),
              nonce: req.nonce,
              sdkDir,
              signal,
            },
          )
        },
        async close() { /* noop */ },
      }
    },
  } as unknown as WorkerBackend

  const res = await runAgentScriptProof({
    script,
    runtime: 'ts',
    broker,
    grant,
    backend,
    runId: 'run-modea-norm',
    assignmentId: 'asg-modea-norm',
    targetOrigins: [liveOrigin],
    signal: AbortSignal.timeout(20_000),
  })
  assert.equal(res.verdict.confirmed, true, `Mode-A fresh-entity chain must confirm instead of transcript_mismatch, got: ${res.verdict.reason}: ${res.verdict.detail}`)
  assert.equal(res.verdict.attempts.length, 2)
})

// ============================================================================
// Requirement 3: Host-Side Backwards Causal Proof Compiler + Ancestor-Cap Rewire
// ============================================================================

test('Req 3: compileCausalChainFromTranscript rebinds mis-anchored ancestor value_binding and infers mutating state_transition_binding', () => {
  const orderCap = 'cap:hop_1:order_id_tok'
  const entityId = 'ord_42_abc'

  const h1 = signedEntry('ex-3-h1', makeStep({
    id: 'ex-3-h1', arm: 'probe', method: 'POST', status: 201, pathAndQuery: '/v1/orders',
    json: { id: entityId, status: 'draft' },
  }), { seq: 1, timestampMs: 1000, emittedCapabilities: [orderCap], entityId })

  const ablation = signedEntry('ex-3-abl', makeStep({
    id: 'ex-3-abl', arm: 'control', method: 'POST', status: 403, pathAndQuery: `/v1/orders/${entityId}/approve`,
    json: { error: 'maker_checker_denied' },
  }), { seq: 2, timestampMs: 1050, replayAttempt: 'ablation_control', entityId })

  // hop_2 mutates the order using hop_1's cap, does NOT re-emit orderCap!
  const h2 = signedEntry('ex-3-h2', makeStep({
    id: 'ex-3-h2', arm: 'probe', method: 'PATCH', status: 200, pathAndQuery: `/v1/orders/${entityId}`,
    json: { id: entityId, creatorId: 'other_user' },
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [orderCap], entityId })

  // hop_3 approves the order, also citing orderCap (emitted by ancestor hop_1, NOT hop_2!)
  const h3 = signedEntry('ex-3-h3', makeStep({
    id: 'ex-3-h3', arm: 'probe', method: 'POST', status: 200, pathAndQuery: `/v1/orders/${entityId}/approve`,
    json: { id: entityId, status: 'approved', amountCents: 75000 },
  }), { seq: 4, timestampMs: 1200, consumedCapabilities: [orderCap], entityId })

  const transcript: HostSignedTranscript = { entries: [h1, ablation, h2, h3] }

  // Worker mis-anchored Edge #1 as hop_2 -> hop_3 using hop_1's handle!
  const misAnchoredReceipt: CompositeProofReceipt = {
    chainId: 'gb-3-ancestor-rewire',
    terminalVulnClass: 'maker_checker_bypass',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders' }, exchangeIds: ['ex-3-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Created order', producedCapabilities: [orderCap], consumedCapabilities: [], entityId },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: `/v1/orders/${entityId}` }, exchangeIds: ['ex-3-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Rebound order owner', producedCapabilities: [], consumedCapabilities: [orderCap], entityId },
      { hopId: 'hop_3', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: `/v1/orders/${entityId}/approve` }, exchangeIds: ['ex-3-h3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Self-approved rebound order', producedCapabilities: [], consumedCapabilities: [orderCap], entityId },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: orderCap },
      { kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_3', capabilityHandle: orderCap },
    ],
    terminalImpact: {
      terminalHopId: 'hop_3',
      terminalExchangeId: 'ex-3-h3',
      summary: 'Maker-checker bypass via order rebind and self-approval.',
      claimedImpact: 'Maker-checker bypass via order rebind and self-approval.',
      preChainControlExchangeIds: ['ex-3-abl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }

  // Direct compiler check: rebinds hop_2->hop_3 to hop_1->hop_3 AND infers mutating state_transition_binding hop_2->hop_3!
  const compiled = compileCausalChainFromTranscript(misAnchoredReceipt, transcript)
  assert.equal(compiled.rewiredEdges.length, 1)
  assert.equal(compiled.rewiredEdges[0]?.fromHopId, 'hop_2')
  assert.equal(compiled.rewiredEdges[0]?.rewiredFromHopId, 'hop_1')
  assert.equal(compiled.rewiredEdges[0]?.toHopId, 'hop_3')
  assert.ok(
    compiled.inferredEdges.some(e => e.kind === 'state_transition_binding' && e.fromHopId === 'hop_2' && e.toHopId === 'hop_3' && e.entityId === entityId),
    `Expected inferred mutating state_transition_binding hop_2->hop_3, got ${JSON.stringify(compiled.inferredEdges)}`,
  )

  // End-to-end verifyCompositeReceipt confirms cleanly with all 3 edges verified!
  const verified = verifyCompositeReceipt(misAnchoredReceipt, transcript, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
  })
  assert.equal(verified.confirmed, true, `Expected ancestor-rewired chain to confirm, got: ${verified.reason}`)
  assert.equal(verified.verifiedEdges.length, 3)
  assert.equal(verified.evidence?.rewiredEdgeCount, 1)
})

// ============================================================================
// Requirement 4: Single-Attempt Fast-Fail on `checkpoint` / `execution` + Guidance
// ============================================================================

test('Req 4: verifyScript fast-fails Attempt 2 on checkpoint and execution, and emits Mode-A single-script guidance + non-secret HTTP shape', async () => {
  // (a) Checkpoint on Attempt 1 -> Attempt 2 skipped, single-script Mode-A hint + non-secret HTTP keys included (values never leaked!)
  let checkpointOpens = 0
  const cpVerdict = await verifyScript({
    candidate: { name: 'cp.ts', runtime: 'ts', code: 'await ctx.http_send("/v1/invites/resolve")' },
    fastFailOnAttempt1: true,
    openAttempt: async ({ nonce }): Promise<VerifyAttemptSession> => {
      checkpointOpens += 1
      const transcript = new TranscriptStore(Buffer.from('secret-cp'))
      transcript.record({
        op: 'http',
        startedAt: Date.now(),
        durationMs: 3,
        request: {
          origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/invites/resolve?secret_q=do_not_echo',
          headers: {}, bodyBytes: 0, bodySha256: 'abc', nonce,
        },
        response: {
          status: 200, headers: { 'content-type': 'application/json' },
          bodyBytes: 42, bodySha256: 'def', mediaType: 'application/json',
        },
        body: JSON.stringify({ inviteToken: 'TOP_SECRET_VALUE_999', orgId: 'org_a' }),
      })
      transcript.record({
        op: 'capability',
        startedAt: Date.now(),
        durationMs: 1,
        request: { origin: ORIGIN, method: 'SEAL', pathAndQuery: '/capability/seal/inv', headers: {}, bodyBytes: 0, bodySha256: 'abc', nonce },
        artifact: { kind: 'capability', capabilityHandle: 'cap:hop_1:inv', artifactDigest: 'abc' },
      })
      return {
        nonce,
        transcript,
        async execute() {
          return { result: { sdk: 'kovo_verify.ts', nonce, title: 'Hop 1', claims: [] }, stdout: '', stderr: '', exitCode: 0, durationMs: 5 }
        },
        async close() { /* noop */ },
      }
    },
  })
  assert.equal(checkpointOpens, 1, 'Checkpoint on Attempt 1 must fast-fail and NOT open Attempt 2')
  assert.equal(cpVerdict.attempts.length, 1)
  assert.equal(cpVerdict.confirmed, false)
  assert.equal(cpVerdict.reason, 'checkpoint_only')
  assert.equal(cpVerdict.rejectedBy, 'checkpoint')
  assert.match(cpVerdict.detail, /Hop 1->N in ONE ctx\.chain\(\.\.\.\)\.prove\(\)/)
  assert.match(cpVerdict.detail, /POST \/v1\/invites\/resolve -> 200 keys=\[inviteToken,orgId\]/)
  assert.doesNotMatch(cpVerdict.detail, /TOP_SECRET_VALUE_999/, 'Secret JSON values must NEVER appear in checkpoint hint')
  assert.doesNotMatch(cpVerdict.detail, /do_not_echo/, 'Query string params must NEVER appear in checkpoint hint')

  // (b) Execution failure on Attempt 1 -> Attempt 2 skipped!
  let execOpens = 0
  const execVerdict = await verifyScript({
    candidate: { name: 'boom.ts', runtime: 'ts', code: 'throw new Error("boom")' },
    fastFailOnAttempt1: true,
    openAttempt: async ({ nonce }): Promise<VerifyAttemptSession> => {
      execOpens += 1
      const transcript = new TranscriptStore(Buffer.from('secret-exec'))
      return {
        nonce,
        transcript,
        async execute() {
          return { result: { error: 'ReferenceError: badVar is not defined' }, stdout: '', stderr: 'ReferenceError: badVar is not defined\n', exitCode: 1, durationMs: 4 }
        },
        async close() { /* noop */ },
      }
    },
  })
  assert.equal(execOpens, 1, 'Execution failure on Attempt 1 must fast-fail and NOT open Attempt 2')
  assert.equal(execVerdict.attempts.length, 1)
  assert.equal(execVerdict.confirmed, false)
  assert.equal(execVerdict.rejectedBy, 'execution')
})
