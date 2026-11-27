// @kernel @fixes R3-05
/**
 * Architecture Kernel Fixes Suite (R3-05):
 *  1. `race` op sub-exchange hydration into `economic_conservation` `actions` (`missing_action_records` fix)
 *     + zero-mutating-action `economic_conservation` fail-closed rejection (stripping host pseudo-ops).
 *  2. Exact-boundary tenant slug/identifier matching (`quanta` NEVER matches `quanta-labs` or `quanta_labs`)
 *     + fail-closed rejection of read-only `access_control` terminals whose tenant markers are purely
 *     request-reflected with zero non-reflected foreign-tenant evidence.
 *  3. Predecessor-ablation & own-org invite-resolution tightening for 2-hop un-ablated own-org invite
 *     resolution flows while preserving legitimate invite-leak -> redeem privilege-escalation TPs
 *     (same-persona 403 control + role escalation) and cross-tenant sibling invite redemptions.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import '../src/server/terminal-oracle-registry.ts'
import {
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import {
  containsExactTenantToken,
  matchesExactTenantIdentifier,
  resolveEconomicActionRecords,
} from '../src/server/own-org-terminal-guard.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'test-arch-kernel-race-v8-signing-key-0123456789'

function makeStep(overrides: Partial<ImpactStep> & { id: string; arm: 'control' | 'probe' }): ImpactStep {
  return {
    method: 'GET',
    pathAndQuery: '/v1/resource',
    status: 200,
    actor: { handle: 'user_a', role: 'member', tenant: 'org_alpha', auth: 'bearer', sameSite: null },
    ...overrides,
  }
}

function signedEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry & { op?: string; raceBatchId?: string | null }> = {},
): HostTranscriptEntry {
  const rec = {
    exchangeId,
    origin: ORIGIN,
    timestampMs: extra.timestampMs ?? 1000,
    seq: extra.seq ?? 1,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : (step.actor.handle ?? 'user_a'),
    actorRoleLabel: extra.actorRoleLabel !== undefined ? extra.actorRoleLabel : `${step.actor.role ?? 'member'} [slug=quanta] (${step.actor.tenant ?? 'org_alpha'})`,
    actorTenant: extra.actorTenant !== undefined ? extra.actorTenant : (step.actor.tenant ?? 'org_alpha'),
    cleanSession: extra.cleanSession ?? true,
    step: { route: step.pathAndQuery?.split('?')[0], ...step },
    ...extra,
  } as HostTranscriptEntry
  return { ...rec, hostSignature: signHostRecord(rec, SIGNING_KEY) }
}

function verify(
  receipt: CompositeProofReceipt,
  entries: HostTranscriptEntry[],
  opts: { attackerPersonas?: string[]; personaRoleLabels?: Record<string, string> } = {},
) {
  const transcript: HostSignedTranscript = { entries }
  const factLog = HostFactLog.fromTranscript(transcript)
  return verifyCompositeReceipt(receipt, transcript, {
    signingKey: SIGNING_KEY,
    factLog,
    attackerPersonas: opts.attackerPersonas ?? ['user_a'],
    personaRoleLabels: opts.personaRoleLabels ?? {
      user_a: 'member [slug=quanta] (org_alpha)',
      user_b: 'member [slug=quanta-labs] (org_beta)',
    },
  })
}

// ============================================================================
// 1. Race Op Sub-Exchange Hydration + Zero-Mutating-Action Rejection
// ============================================================================

test('1A: hydrates DAG-bound race op sub-exchanges from oracleInput.actionExchangeIds into economic_conservation actions', () => {
  const ordCap = 'cap:hop_create:ord_cap_1'
  const batchId = 'race_batch_001'

  const baseBal = signedEntry('ec-base', makeStep({
    id: 'ec-base', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/balance', json: { tenant: 'org_alpha', balanceCents: 100000 },
  }), { seq: 1, timestampMs: 1000 })

  const create = signedEntry('ec-create', makeStep({
    id: 'ec-create', arm: 'probe', method: 'POST', status: 201,
    pathAndQuery: '/v1/orders', requestJson: { amountCents: 5000 },
    json: { order: { id: 'ord_101', amountCents: 5000, status: 'draft' } },
  }), { seq: 2, timestampMs: 1100, emittedCapabilities: [ordCap] })

  const rebind = signedEntry('ec-rebind', makeStep({
    id: 'ec-rebind', arm: 'probe', method: 'PATCH', status: 200,
    pathAndQuery: '/v1/orders/ord_101/rebind', requestJson: { beneficiary: 'acct_1' },
    json: { order: { id: 'ord_101', amountCents: 5000, status: 'authorized' } },
  }), { seq: 3, timestampMs: 1200, consumedCapabilities: [ordCap] })

  const raceEntries = Array.from({ length: 4 }, (_, i) => signedEntry(`ec-race-${i}`, makeStep({
    id: `ec-race-${i}`, arm: 'probe', method: 'POST', status: i === 0 ? 200 : 409,
    pathAndQuery: '/v1/orders/ord_101/capture',
    json: i === 0 ? { order: { id: 'ord_101', amountCents: 5000, status: 'settled' }, capture: 1 } : { error: 'already_settled' },
  }), { seq: 4 + i, timestampMs: 1300, op: 'race', raceBatchId: batchId, consumedCapabilities: [ordCap] }))

  const finBal = signedEntry('ec-fin', makeStep({
    id: 'ec-fin', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/balance', json: { tenant: 'org_alpha', balanceCents: 158000 },
  }), { seq: 10, timestampMs: 1400 })

  // Worker cites race sub-exchanges in oracleInput.actionExchangeIds while hops hold create -> rebind
  const receipt: CompositeProofReceipt = {
    chainId: 'race-actions-outside-hops',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'create', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders' }, exchangeIds: ['ec-create'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Create draft order', producedCapabilities: [ordCap], consumedCapabilities: [] },
      { hopId: 'rebind', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/v1/orders/ord_101/rebind' }, exchangeIds: ['ec-rebind'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Authorize order for capture', producedCapabilities: [], consumedCapabilities: [ordCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'create', toHopId: 'rebind', capabilityHandle: ordCap }],
    terminalImpact: {
      terminalHopId: 'rebind',
      summary: 'Concurrent capture race minted excess balance beyond order amount.',
      claimedImpact: 'Concurrent capture race minted excess balance beyond order amount.',
      oracleFamily: 'economic_conservation',
      oracleInput: {
        baselineReadbackExchangeId: 'ec-base',
        finalReadbackExchangeId: 'ec-fin',
        actionExchangeIds: raceEntries.map(e => e.exchangeId),
      },
      preChainControlExchangeIds: ['ec-base'],
      postChainReadbackExchangeIds: ['ec-fin'],
    },
    replayMode: 'fresh_clean_replay',
  }

  const res = verify(receipt, [baseBal, create, rebind, ...raceEntries, finBal])
  assert.equal(res.confirmed, true, `Expected race actionExchangeIds to hydrate cleanly, got: ${res.reason}`)
  assert.equal(res.terminalOracleFamily, 'economic_conservation')

  // 3-hop DAG (create -> rebind -> race capture hop) with auto-hydrated race batch also confirms cleanly
  const rebindCap = 'cap:hop_rebind:auth_1'
  const rebind3 = signedEntry('ec3-rebind', makeStep({
    id: 'ec3-rebind', arm: 'probe', method: 'PATCH', status: 200,
    pathAndQuery: '/v1/orders/ord_101/rebind', requestJson: { beneficiary: 'acct_1' },
    json: { order: { id: 'ord_101', amountCents: 5000, status: 'authorized' } },
  }), { seq: 3, timestampMs: 1200, consumedCapabilities: [ordCap], emittedCapabilities: [rebindCap] })
  const race3 = raceEntries.map((e, i) => signedEntry(`ec3-race-${i}`, makeStep({
    id: `ec3-race-${i}`, arm: 'probe', method: 'POST', status: i === 0 ? 200 : 409,
    pathAndQuery: '/v1/orders/ord_101/capture',
    json: i === 0 ? { order: { id: 'ord_101', amountCents: 5000, status: 'settled' }, capture: 1 } : { error: 'already_settled' },
  }), { seq: 4 + i, timestampMs: 1300, op: 'race', raceBatchId: 'race_batch_003', consumedCapabilities: [ordCap, rebindCap] }))

  const receipt3: CompositeProofReceipt = {
    chainId: 'race-3hop-auto-expand',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'create', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders' }, exchangeIds: ['ec-create'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Create order', producedCapabilities: [ordCap], consumedCapabilities: [] },
      { hopId: 'rebind', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/v1/orders/ord_101/rebind' }, exchangeIds: ['ec3-rebind'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Rebind order', producedCapabilities: [rebindCap], consumedCapabilities: [ordCap] },
      { hopId: 'capture', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/ord_101/capture' }, exchangeIds: ['ec3-race-0'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Execute concurrent capture burst', producedCapabilities: [], consumedCapabilities: [rebindCap] },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'create', toHopId: 'rebind', capabilityHandle: ordCap },
      { kind: 'value_binding', fromHopId: 'rebind', toHopId: 'capture', capabilityHandle: rebindCap },
    ],
    terminalImpact: {
      terminalHopId: 'capture',
      terminalExchangeId: 'ec3-race-0',
      summary: 'Three-hop create -> rebind -> race capture burst minted excess balance.',
      claimedImpact: 'Three-hop create -> rebind -> race capture burst minted excess balance.',
      oracleFamily: 'economic_conservation',
      oracleInput: {
        baselineReadbackExchangeId: 'ec-base',
        finalReadbackExchangeId: 'ec-fin',
      },
      preChainControlExchangeIds: ['ec-base'],
      postChainReadbackExchangeIds: ['ec-fin'],
    },
    replayMode: 'fresh_clean_replay',
  }
  const res3 = verify(receipt3, [baseBal, create, rebind3, ...race3, finBal])
  assert.equal(res3.confirmed, true, `Expected 3-hop race hop DAG to confirm, got: ${res3.reason}`)
})

test('1B: rejects zero-mutating-action economic_conservation receipts (host pseudo-ops, GET-only, and unbound non-race actions)', () => {
  const baseBal = signedEntry('zm-base', makeStep({
    id: 'zm-base', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/balance', json: { tenant: 'org_alpha', balanceCents: 10000 },
  }), { seq: 1, timestampMs: 1000 })

  const sealOp = signedEntry('zm-seal', makeStep({
    id: 'zm-seal', arm: 'probe', method: 'SEAL', status: 200,
    pathAndQuery: '/capability/seal/c1', json: {},
  }), { seq: 2, timestampMs: 1100, op: 'capability', evidenceRole: 'host_capability_op' })

  const readOnly = signedEntry('zm-get', makeStep({
    id: 'zm-get', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/orders/ord_1', json: { order: { id: 'ord_1', amountCents: 100 } },
  }), { seq: 3, timestampMs: 1200 })

  const unboundHttpPost = signedEntry('zm-unbound-post', makeStep({
    id: 'zm-unbound-post', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/v1/orders/ord_other/capture', json: { ok: true },
  }), { seq: 4, timestampMs: 1250, op: 'http' })

  const finBal = signedEntry('zm-fin', makeStep({
    id: 'zm-fin', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/balance', json: { tenant: 'org_alpha', balanceCents: 50000 },
  }), { seq: 5, timestampMs: 1300 })

  const entriesMap = new Map([baseBal, sealOp, readOnly, unboundHttpPost, finBal].map(e => [e.exchangeId, e]))

  // Host pseudo-op (SEAL) must be stripped -> 0 actions!
  const sealOnly = resolveEconomicActionRecords({
    rawActRecs: [{ id: 'zm-seal', hostSignature: 'sig-12345678', timestampMs: 1100, method: 'SEAL', status: 200 }],
    entriesById: entriesMap,
    citedExchangeIds: ['zm-seal'],
  })
  assert.equal(sealOnly.length, 0, 'Host pseudo-op SEAL must never count as a mutating economic action')

  // Uncited non-race HTTP POST must stay excluded!
  const uncitedNonRace = resolveEconomicActionRecords({
    rawActRecs: [{ id: 'zm-unbound-post', hostSignature: 'sig-12345678', timestampMs: 1250, method: 'POST', status: 200 }],
    entriesById: entriesMap,
    citedExchangeIds: ['zm-get'],
    baseRec: { id: 'zm-base', hostSignature: 'sig-12345678', timestampMs: 1000, method: 'GET', status: 200 },
    finRec: { id: 'zm-fin', hostSignature: 'sig-12345678', timestampMs: 1300, method: 'GET', status: 200 },
  })
  assert.equal(uncitedNonRace.length, 0, 'Uncited non-race POST must remain excluded')

  // End-to-end receipt with only GET hop + empty/GET actions fails closed
  const zeroMutReceipt: CompositeProofReceipt = {
    chainId: 'zero-mutating-econ',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'obs', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/orders/ord_1' }, exchangeIds: ['zm-get'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read order state', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'obs',
      terminalExchangeId: 'zm-get',
      summary: 'Read-only observation claiming balance drift without mutating probe.',
      claimedImpact: 'Read-only observation claiming balance drift without mutating probe.',
      oracleFamily: 'economic_conservation',
      oracleInput: {
        baselineReadbackExchangeId: 'zm-base',
        finalReadbackExchangeId: 'zm-fin',
        actionExchangeIds: ['zm-get'],
      },
      preChainControlExchangeIds: ['zm-base'],
      postChainReadbackExchangeIds: ['zm-fin'],
    },
    replayMode: 'fresh_clean_replay',
  }
  const resGet = verify(zeroMutReceipt, [baseBal, sealOp, readOnly, finBal])
  assert.equal(resGet.confirmed, false)
  assert.match(resGet.reason, /action_not_mutating|missing_action_records/i)
})

// ============================================================================
// 2. Exact-Boundary Tenant Matching & Reflected-Only Export Read Rejection
// ============================================================================

test('2A: exact-boundary tenant identifier matching prevents quanta vs quanta-labs prefix confusion', () => {
  assert.equal(matchesExactTenantIdentifier('quanta', 'quanta'), true)
  assert.equal(matchesExactTenantIdentifier('Quanta', 'quanta'), true)
  assert.equal(matchesExactTenantIdentifier('quanta', 'quanta-labs'), false)
  assert.equal(matchesExactTenantIdentifier('quanta-labs', 'quanta'), false)
  assert.equal(matchesExactTenantIdentifier('quanta', 'quanta_labs'), false)
  assert.equal(matchesExactTenantIdentifier('my-quanta', 'quanta'), false)

  assert.equal(containsExactTenantToken('tenant=quanta-labs;export=1', 'quanta'), false)
  assert.equal(containsExactTenantToken('tenant=quanta_labs;export=1', 'quanta'), false)
  assert.equal(containsExactTenantToken('tenant=my-quanta;export=1', 'quanta'), false)
  assert.equal(containsExactTenantToken('tenant=quanta-labs;export=1', 'quanta-labs'), true)
  assert.equal(containsExactTenantToken('tenant: quanta, status: ok', 'quanta'), true)
})

test('2B: rejects reflected-tenant-only CSV export download under broken_access_control while preserving genuine foreign-tenant reads', () => {
  const jobCap = 'cap:hop_export:job_1'
  const ctrl403 = signedEntry('ex-ctrl-csv', makeStep({
    id: 'ex-ctrl-csv', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/files/export/quanta-labs/report-quanta.csv?tenant=quanta&sig=bad',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000 })

  const createExp = signedEntry('ex-create-csv', makeStep({
    id: 'ex-create-csv', arm: 'probe', method: 'POST', status: 202,
    pathAndQuery: '/v1/orgs/quanta/exports',
    json: { jobId: 'job_1', tenant: 'org_alpha' },
  }), { seq: 2, timestampMs: 1100, emittedCapabilities: [jobCap] })

  // Non-JSON CSV whose only tenant marker (`quanta-labs`) is already in the request path -> reflectedTenantOnly!
  const csvRead = signedEntry('ex-read-csv', makeStep({
    id: 'ex-read-csv', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/files/export/quanta-labs/report-quanta.csv?tenant=quanta&sig=valid',
    responseHeaders: { 'content-type': 'text/csv; charset=utf-8' },
    body: 'tenant,quanta-labs\nbalance_cents,50000\n',
  }), { seq: 3, timestampMs: 1200, consumedCapabilities: [jobCap] })

  const reflReceipt: CompositeProofReceipt = {
    chainId: 'reflected-export-prefix-fp',
    terminalVulnClass: 'broken_access_control',
    hops: [
      { hopId: 'create', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orgs/quanta/exports' }, exchangeIds: ['ex-create-csv'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Create own export job', producedCapabilities: [jobCap], consumedCapabilities: [] },
      { hopId: 'read', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/files/export/quanta-labs/report-quanta.csv?tenant=quanta&sig=valid' }, exchangeIds: ['ex-read-csv'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Fetch CSV export', producedCapabilities: [], consumedCapabilities: [jobCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'create', toHopId: 'read', capabilityHandle: jobCap }],
    terminalImpact: {
      terminalHopId: 'read',
      terminalExchangeId: 'ex-read-csv',
      summary: 'Export download reflected request path tenant marker without foreign evidence.',
      claimedImpact: 'Export download reflected request path tenant marker without foreign evidence.',
      preChainControlExchangeIds: ['ex-ctrl-csv'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }

  const reflRes = verify(reflReceipt, [ctrl403, createExp, csvRead])
  assert.equal(reflRes.confirmed, false, 'Reflected-tenant-only CSV read must fail closed under broken_access_control')
  assert.equal(reflRes.rejectedBy, 'terminal_impact_unproven')

  // Legitimate foreign-tenant read where response contains non-reflected foreign tenant JSON data STILL PASSES
  const docCap = 'cap:hop_leak:doc_key'
  const docCtrl = signedEntry('doc-ctrl', makeStep({
    id: 'doc-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/v1/docs/doc_foreign_99/content', json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000 })
  const docLeak = signedEntry('doc-leak', makeStep({
    id: 'doc-leak', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/public/profile/shared.css', body: '/* token */',
  }), { seq: 2, timestampMs: 1100, emittedCapabilities: [docCap] })
  const docRead = signedEntry('doc-read', makeStep({
    id: 'doc-read', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/docs/doc_foreign_99/content',
    json: { id: 'doc_foreign_99', tenant: 'org_beta', body: 'confidential foreign document payload' },
  }), { seq: 3, timestampMs: 1200, consumedCapabilities: [docCap] })

  const foreignRes = verify({
    chainId: 'legit-foreign-doc-read',
    terminalVulnClass: 'broken_access_control',
    hops: [
      { hopId: 'leak', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/public/profile/shared.css' }, exchangeIds: ['doc-leak'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtain delegation key', producedCapabilities: [docCap], consumedCapabilities: [] },
      { hopId: 'read', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/docs/doc_foreign_99/content' }, exchangeIds: ['doc-read'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read foreign document content', producedCapabilities: [], consumedCapabilities: [docCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'leak', toHopId: 'read', capabilityHandle: docCap }],
    terminalImpact: {
      terminalHopId: 'read',
      terminalExchangeId: 'doc-read',
      summary: 'Cross-tenant delegation key unlocks foreign tenant private document.',
      claimedImpact: 'Cross-tenant delegation key unlocks foreign tenant private document.',
      preChainControlExchangeIds: ['doc-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, [docCtrl, docLeak, docRead])
  assert.equal(foreignRes.confirmed, true, `Legitimate foreign-tenant read must still pass, got: ${foreignRes.reason}`)
})

// ============================================================================
// 3. Predecessor-Ablation & Own-Org Authorized Invite-Resolution Tightening
// ============================================================================

test('3A: rejects 2-hop own-org flows starting directly at un-ablated invite resolution (with or without post-mutation readback)', () => {
  const invCap = 'cap:hop_resolve:own_tok'

  const ctrlApprove = signedEntry('inv-ctrl-app', makeStep({
    id: 'inv-ctrl-app', arm: 'control', method: 'POST', status: 403,
    pathAndQuery: '/v1/payouts/pay_77/approve', json: { error: 'finance_role_required' },
  }), { seq: 1, timestampMs: 1000 })

  const resolveOwn = signedEntry('inv-resolve-own', makeStep({
    id: 'inv-resolve-own', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/invites/resolve',
    requestJson: { email: 'fin@quanta.example', orgSlug: 'quanta' },
    json: { token: 'tok_fin_12345', tenant: 'quanta', role: 'finance', verified: false },
  }), { seq: 2, timestampMs: 1100, emittedCapabilities: [invCap] })

  const approveOwn = signedEntry('inv-approve-own', makeStep({
    id: 'inv-approve-own', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/v1/payouts/pay_77/approve',
    json: { payout: { id: 'pay_77', tenantId: 'org_alpha', status: 'settled', amountCents: 49000 } },
  }), { seq: 3, timestampMs: 1200, actorPersona: invCap, consumedCapabilities: [invCap] })

  const rbOwn = signedEntry('inv-rb-own', makeStep({
    id: 'inv-rb-own', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/payouts/pay_77',
    json: { payout: { id: 'pay_77', tenantId: 'org_alpha', status: 'settled', amountCents: 49000 } },
  }), { seq: 4, timestampMs: 1300, actorPersona: invCap, consumedCapabilities: [invCap] })

  const fpPayoutRes = verify({
    chainId: 'own-org-root-invite-approve-fp',
    terminalVulnClass: 'business_logic',
    hops: [
      { hopId: 'resolve', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/resolve' }, exchangeIds: ['inv-resolve-own'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Resolve own-org invite', producedCapabilities: [invCap], consumedCapabilities: [] },
      { hopId: 'approve', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/payouts/pay_77/approve' }, exchangeIds: ['inv-approve-own'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Approve own-org payout', producedCapabilities: [], consumedCapabilities: [invCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'resolve', toHopId: 'approve', capabilityHandle: invCap }],
    terminalImpact: {
      terminalHopId: 'approve',
      terminalExchangeId: 'inv-approve-own',
      summary: '2-hop own-org invite resolution without predecessor leak or invite ablation.',
      claimedImpact: '2-hop own-org invite resolution without predecessor leak or invite ablation.',
      preChainControlExchangeIds: ['inv-ctrl-app'],
      postChainReadbackExchangeIds: ['inv-rb-own'],
    },
    replayMode: 'fresh_clean_replay',
  }, [ctrlApprove, resolveOwn, approveOwn, rbOwn])
  assert.equal(fpPayoutRes.confirmed, false, 'Un-ablated 2-hop own-org invite resolution -> payout approve must fail closed')
  assert.equal(fpPayoutRes.rejectedBy, 'terminal_impact_unproven')

  // Also reject 2-hop own-org invite resolution -> own-org invite creation (privilege_escalation)
  const ownerCap = 'cap:hop_resolve:owner_tok'
  const ctrlInv = signedEntry('inv2-ctrl', makeStep({
    id: 'inv2-ctrl', arm: 'control', method: 'POST', status: 403,
    pathAndQuery: '/v1/orgs/quanta/invites', json: { error: 'owner_required' },
  }), { seq: 1, timestampMs: 1000 })
  const resolveOwner = signedEntry('inv2-resolve', makeStep({
    id: 'inv2-resolve', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/invites/resolve',
    requestJson: { email: 'owner@quanta.example', orgSlug: 'quanta' },
    json: { token: 'tok_owner_9876', tenant: 'quanta', role: 'owner', verified: true },
  }), { seq: 2, timestampMs: 1100, emittedCapabilities: [ownerCap] })
  const createOwnerInv = signedEntry('inv2-create', makeStep({
    id: 'inv2-create', arm: 'probe', method: 'POST', status: 201,
    pathAndQuery: '/v1/orgs/quanta/invites',
    requestJson: { email: 'new@quanta.example', role: 'owner' },
    json: { id: 'inv_new_1', role: 'owner', tenant: 'org_alpha' },
  }), { seq: 3, timestampMs: 1200, actorPersona: ownerCap, consumedCapabilities: [ownerCap] })
  const rbInv = signedEntry('inv2-rb', makeStep({
    id: 'inv2-rb', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/orgs/quanta/invites',
    json: { invites: [{ id: 'inv_new_1', role: 'owner', tenant: 'org_alpha' }] },
  }), { seq: 4, timestampMs: 1300, actorPersona: ownerCap, consumedCapabilities: [ownerCap] })

  const fpOwnerRes = verify({
    chainId: 'own-org-root-invite-owner-fp',
    terminalVulnClass: 'privilege_escalation',
    hops: [
      { hopId: 'resolve', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/resolve' }, exchangeIds: ['inv2-resolve'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Resolve own-org owner invite', producedCapabilities: [ownerCap], consumedCapabilities: [] },
      { hopId: 'create_inv', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orgs/quanta/invites' }, exchangeIds: ['inv2-create'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Create invite in own org', producedCapabilities: [], consumedCapabilities: [ownerCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'resolve', toHopId: 'create_inv', capabilityHandle: ownerCap }],
    terminalImpact: {
      terminalHopId: 'create_inv',
      terminalExchangeId: 'inv2-create',
      summary: '2-hop own-org owner invite resolution without predecessor compromise.',
      claimedImpact: '2-hop own-org owner invite resolution without predecessor compromise.',
      preChainControlExchangeIds: ['inv2-ctrl'],
      postChainReadbackExchangeIds: ['inv2-rb'],
    },
    replayMode: 'fresh_clean_replay',
  }, [ctrlInv, resolveOwner, createOwnerInv, rbInv])
  assert.equal(fpOwnerRes.confirmed, false, 'Un-ablated 2-hop own-org invite resolution -> invite create must fail closed')
  assert.equal(fpOwnerRes.rejectedBy, 'terminal_impact_unproven')

  // Direct own-org invite-resolution terminal with same-role (no escalation) fails closed
  const ctrlRedeem = signedEntry('inv3-ctrl', makeStep({
    id: 'inv3-ctrl', arm: 'control', method: 'POST', status: 403,
    pathAndQuery: '/invites/redeem', json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000 })
  const leakInv = signedEntry('inv3-leak', makeStep({
    id: 'inv3-leak', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/invites', json: { invites: [{ id: 'i1', role: 'member', token: 'tok_mem_1' }] },
  }), { seq: 2, timestampMs: 1100, emittedCapabilities: ['cap:inv3:tok'] })
  const redeemSameRole = signedEntry('inv3-redeem', makeStep({
    id: 'inv3-redeem', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/invites/redeem',
    json: { token: 'sess_mem_999', tenant: 'quanta', role: 'member' },
  }), { seq: 3, timestampMs: 1200, consumedCapabilities: ['cap:inv3:tok'] })

  const sameRoleRes = verify({
    chainId: 'own-org-same-role-redeem-fp',
    terminalVulnClass: 'privilege_escalation',
    hops: [
      { hopId: 'leak', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/invites' }, exchangeIds: ['inv3-leak'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read own invite list', producedCapabilities: ['cap:inv3:tok'], consumedCapabilities: [] },
      { hopId: 'redeem', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/redeem' }, exchangeIds: ['inv3-redeem'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Redeem same-tier member invite', producedCapabilities: [], consumedCapabilities: ['cap:inv3:tok'] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'leak', toHopId: 'redeem', capabilityHandle: 'cap:inv3:tok' }],
    terminalImpact: {
      terminalHopId: 'redeem',
      terminalExchangeId: 'inv3-redeem',
      summary: 'Redeeming own-tenant invite with identical member role is not escalation.',
      claimedImpact: 'Redeeming own-tenant invite with identical member role is not escalation.',
      preChainControlExchangeIds: ['inv3-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, [ctrlRedeem, leakInv, redeemSameRole])
  assert.equal(sameRoleRes.confirmed, false, 'Own-tenant invite redemption with same role must fail closed')
  assert.equal(sameRoleRes.rejectedBy, 'terminal_impact_unproven')
})

test('3B: preserves legitimate invite-leak -> redeem privilege-escalation TP (same-persona 403 control + role escalation) and sibling-tenant redemption', () => {
  const leakCap = 'cap:tp_inv:leaked_tok'
  const sessCap = 'cap:tp_inv:admin_sess'

  const ctrl403 = signedEntry('tp-inv-ctrl', makeStep({
    id: 'tp-inv-ctrl', arm: 'control', method: 'POST', status: 403,
    pathAndQuery: '/invites/redeem', json: { error: 'invite not redeemable' },
  }), { seq: 1, timestampMs: 1000 })

  const leak = signedEntry('tp-inv-leak', makeStep({
    id: 'tp-inv-leak', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/invites',
    json: { invites: [{ id: 'inv_adm_1', tenant: 'org_alpha', role: 'admin', token: 'inv_secret_tok' }] },
  }), { seq: 2, timestampMs: 1100, emittedCapabilities: [leakCap] })

  const redeem = signedEntry('tp-inv-redeem', makeStep({
    id: 'tp-inv-redeem', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/invites/redeem',
    json: { token: 'admin_sess_tok_42', tenant: 'quanta', role: 'admin' },
  }), { seq: 3, timestampMs: 1200, consumedCapabilities: [leakCap], emittedCapabilities: [sessCap] })

  const meRb = signedEntry('tp-inv-me', makeStep({
    id: 'tp-inv-me', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/me',
    json: { userId: 'usr_a', tenant: 'org_alpha', role: 'admin' },
  }), { seq: 4, timestampMs: 1300, actorPersona: sessCap, consumedCapabilities: [sessCap] })

  const tpRes = verify({
    chainId: 'tp-invite-leak-redeem-escalation',
    terminalVulnClass: 'broken_access_control',
    hops: [
      { hopId: 'leak', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/invites' }, exchangeIds: ['tp-inv-leak'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Leak admin invite token', producedCapabilities: [leakCap], consumedCapabilities: [] },
      { hopId: 'redeem', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/redeem' }, exchangeIds: ['tp-inv-redeem'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Redeem leaked admin invite after 403 control', producedCapabilities: [sessCap], consumedCapabilities: [leakCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'leak', toHopId: 'redeem', capabilityHandle: leakCap }],
    terminalImpact: {
      terminalHopId: 'redeem',
      terminalExchangeId: 'tp-inv-redeem',
      summary: 'Leaked invite redemption escalates member to admin after verified 403 control.',
      claimedImpact: 'Leaked invite redemption escalates member to admin after verified 403 control.',
      preChainControlExchangeIds: ['tp-inv-ctrl'],
      postChainReadbackExchangeIds: ['tp-inv-me'],
    },
    replayMode: 'fresh_clean_replay',
  }, [ctrl403, leak, redeem, meRb])
  assert.equal(tpRes.confirmed, true, `Legitimate invite-leak -> redeem TP must stay PASSING, got: ${tpRes.reason}`)

  // Cross-tenant sibling invite (`quanta-labs` redeemed by `quanta` user) MUST NOT be confused as own-tenant!
  const sibRedeem = signedEntry('tp-sib-redeem', makeStep({
    id: 'tp-sib-redeem', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/invites/redeem',
    json: { token: 'sib_sess_tok_99', tenant: 'quanta-labs', role: 'member' },
  }), { seq: 3, timestampMs: 1200, consumedCapabilities: [leakCap] })

  const sibRes = verify({
    chainId: 'tp-sibling-tenant-invite-redeem',
    terminalVulnClass: 'broken_access_control',
    hops: [
      { hopId: 'leak', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/invites' }, exchangeIds: ['tp-inv-leak'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Leak sibling invite token', producedCapabilities: [leakCap], consumedCapabilities: [] },
      { hopId: 'redeem', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/redeem' }, exchangeIds: ['tp-sib-redeem'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Redeem sibling tenant invite', producedCapabilities: [], consumedCapabilities: [leakCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'leak', toHopId: 'redeem', capabilityHandle: leakCap }],
    terminalImpact: {
      terminalHopId: 'redeem',
      terminalExchangeId: 'tp-sib-redeem',
      summary: 'Attacker in quanta redeems invite for distinct sibling tenant quanta-labs.',
      claimedImpact: 'Attacker in quanta redeems invite for distinct sibling tenant quanta-labs.',
      preChainControlExchangeIds: ['tp-inv-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, [ctrl403, leak, sibRedeem])
  assert.equal(sibRes.confirmed, true, `Distinct sibling tenant quanta-labs invite redemption must pass, got: ${sibRes.reason}`)
})

// ============================================================================
// 4. R3-05 independent review (claude-opus-5-5-high) bypass-variant regressions
// ============================================================================
const ost = (o: Partial<ImpactStep> & { id: string; arm: 'control' | 'probe' }): ImpactStep => ({ method: 'GET', pathAndQuery: '/v1/resource', status: 200, actor: { handle: 'user_a', role: 'member', tenant: 'org_alpha', auth: 'bearer', sameSite: null }, ...o })
const ose = (id: string, step: ImpactStep, extra: Partial<HostTranscriptEntry> & { op?: string; raceBatchId?: string } = {}): HostTranscriptEntry => {
  const rec = { exchangeId: id, origin: ORIGIN, timestampMs: extra.timestampMs ?? 1000, seq: extra.seq ?? 1, actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : (step.actor.handle ?? 'user_a'), actorRoleLabel: `${step.actor.role ?? 'member'} [slug=quanta] (org_alpha)`, actorTenant: 'org_alpha', cleanSession: true, step: { route: step.pathAndQuery?.split('?')[0], ...step }, ...extra } as HostTranscriptEntry
  return { ...rec, hostSignature: signHostRecord(rec, SIGNING_KEY) }
}
const orun = (r: CompositeProofReceipt, entries: HostTranscriptEntry[]) => {
  const t = { entries }
  return verifyCompositeReceipt(r, t, { signingKey: SIGNING_KEY, factLog: HostFactLog.fromTranscript(t), attackerPersonas: ['user_a'], personaRoleLabels: { user_a: 'member [slug=quanta] (org_alpha)', user_b: 'member [slug=quanta-labs] (org_beta)' } })
}
const ohop = (hopId: string, method: string, p: string, ex: string[], prod: string[], cons: string[]) => ({ hopId, surface: 'http' as const, target: { origin: ORIGIN, method, pathAndQuery: p }, exchangeIds: ex, oobEventIds: [], browserTraceIds: [], claimedDelta: hopId, producedCapabilities: prod, consumedCapabilities: cons })
const oout = (name: string, r: { confirmed: boolean; rejectedBy?: string | null; reason?: string }) => {
  const expectTp = /-TP-/.test(name)
  assert.equal(r.confirmed, expectTp, `${name}: expected confirmed=${expectTp}, got ${r.confirmed} (${r.reason ?? ''})`)
  if (!expectTp) assert.equal(r.rejectedBy, 'terminal_impact_unproven', name)
}

function caseA(name: string, resolvePath: string, resolveJson: Record<string, unknown>, reqJson: Record<string, unknown>, pad: boolean) {
  const cap = 'cap:hop_resolve:own_tok', meCap = 'cap:me:uid'
  const ctrl = ose('c', ost({ id: 'c', arm: 'control', method: 'POST', status: 403, pathAndQuery: '/v1/payouts/pay_77/approve', json: { error: 'finance_role_required' } }), { seq: 1, timestampMs: 1000 })
  const me = ose('me', ost({ id: 'me', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/me', json: { userId: 'usr_a', email: 'a@x.example' } }), { seq: 2, timestampMs: 1050, emittedCapabilities: [meCap] })
  const res = ose('r', ost({ id: 'r', arm: 'probe', method: 'POST', status: 200, pathAndQuery: resolvePath, requestJson: reqJson, json: resolveJson }), { seq: 3, timestampMs: 1100, emittedCapabilities: [cap], ...(pad ? { consumedCapabilities: [meCap] } : {}) })
  const app = ose('a', ost({ id: 'a', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/v1/payouts/pay_77/approve', json: { payout: { id: 'pay_77', tenantId: 'org_alpha', status: 'settled', amountCents: 49000 } } }), { seq: 4, timestampMs: 1200, actorPersona: cap, consumedCapabilities: [cap] })
  const rb = ose('rb', ost({ id: 'rb', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/v1/payouts/pay_77', json: { payout: { id: 'pay_77', tenantId: 'org_alpha', status: 'settled', amountCents: 49000 } } }), { seq: 5, timestampMs: 1300, actorPersona: cap, consumedCapabilities: [cap] })
  const hops = [...(pad ? [ohop('me', 'GET', '/v1/me', ['me'], [meCap], [])] : []), ohop('resolve', 'POST', resolvePath, ['r'], [cap], pad ? [meCap] : []), ohop('approve', 'POST', '/v1/payouts/pay_77/approve', ['a'], [], [cap])]
  const edges = [...(pad ? [{ kind: 'value_binding' as const, fromHopId: 'me', toHopId: 'resolve', capabilityHandle: meCap }] : []), { kind: 'value_binding' as const, fromHopId: 'resolve', toHopId: 'approve', capabilityHandle: cap }]
  oout(name, orun({ chainId: name, terminalVulnClass: 'business_logic', hops, causalEdges: edges, terminalImpact: { terminalHopId: 'approve', terminalExchangeId: 'a', summary: 'Variant chain escalates via invite resolution to privileged action.', claimedImpact: 'Variant chain escalates via invite resolution to privileged action.', preChainControlExchangeIds: ['c'], postChainReadbackExchangeIds: ['rb'] }, replayMode: 'fresh_clean_replay' } as CompositeProofReceipt, pad ? [ctrl, me, res, app, rb] : [ctrl, res, app, rb]))
}

function caseB(name: string, cls: string, pad: boolean, leak: boolean, role: string, redeemPath = '/invites/redeem') {
  const lc = 'cap:inv:tok', meCap = 'cap:me:uid'
  const ctrl = ose('c', ost({ id: 'c', arm: 'control', method: 'POST', status: 403, pathAndQuery: redeemPath, json: { error: 'forbidden' } }), { seq: 1, timestampMs: 1000 })
  const me = ose('me', ost({ id: 'me', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/me', json: { userId: 'usr_a', inviteRef: 'tok_mem_1' } }), { seq: 2, timestampMs: 1050, emittedCapabilities: [leak ? meCap : lc] })
  const lk = ose('l', ost({ id: 'l', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/invites', json: { invites: [{ id: 'i1', role, token: 'tok_mem_1' }] } }), { seq: 3, timestampMs: 1100, emittedCapabilities: [lc], ...(pad && leak ? { consumedCapabilities: [meCap] } : {}) })
  const rd = ose('d', ost({ id: 'd', arm: 'probe', method: 'POST', status: 200, pathAndQuery: redeemPath, json: { token: 'sess_999x', tenant: 'quanta', role } }), { seq: 4, timestampMs: 1200, consumedCapabilities: [lc] })
  const hops: ReturnType<typeof ohop>[] = [], edges: { kind: 'value_binding'; fromHopId: string; toHopId: string; capabilityHandle: string }[] = [], ents = [ctrl]
  if (pad) { hops.push(ohop('me', 'GET', '/v1/me', ['me'], [leak ? meCap : lc], [])); ents.push(me) }
  if (leak) { hops.push(ohop('leak', 'GET', '/invites', ['l'], [lc], pad ? [meCap] : [])); ents.push(lk); if (pad) edges.push({ kind: 'value_binding', fromHopId: 'me', toHopId: 'leak', capabilityHandle: meCap }) }
  hops.push(ohop('redeem', 'POST', redeemPath, ['d'], [], [lc])); ents.push(rd)
  edges.push({ kind: 'value_binding', fromHopId: leak ? 'leak' : 'me', toHopId: 'redeem', capabilityHandle: lc })
  oout(name, orun({ chainId: name, terminalVulnClass: cls, hops, causalEdges: edges, terminalImpact: { terminalHopId: 'redeem', terminalExchangeId: 'd', summary: 'Variant chain escalates via invite resolution to privileged action.', claimedImpact: 'Variant chain escalates via invite resolution to privileged action.', preChainControlExchangeIds: ['c'], postChainReadbackExchangeIds: [] }, replayMode: 'fresh_clean_replay' } as CompositeProofReceipt, ents))
}

test('4 (R3-05 opus review): invite path spelling, tenant-less session, /me hop padding, and race route-family binding fail closed; leak->escalation TPs preserved', () => {
  caseA('A0-baseline-author-fp', '/invites/resolve', { token: 'tok_fin_12345', tenant: 'quanta', role: 'finance', verified: false }, { orgSlug: 'quanta' }, false)
  caseA('A1-invitations-path', '/invitations/resolve', { token: 'tok_fin_12345', tenant: 'quanta', role: 'finance', verified: false }, { orgSlug: 'quanta' }, false)
  caseA('A2-invites-id-accept', '/invites/inv_77/accept', { token: 'tok_fin_12345', tenant: 'quanta', role: 'finance', verified: false }, { orgSlug: 'quanta' }, false)
  caseA('A2b-upper-trailing', '/Invites/Accept/', { token: 'tok_fin_12345', tenant: 'quanta', role: 'finance', verified: false }, { orgSlug: 'quanta' }, false)
  caseA('A3-no-tenant-verified', '/invites/resolve', { token: 'tok_fin_12345', role: 'finance' }, { email: 'fin@x.example' }, false)
  caseA('A4-pad-me-3hop', '/invites/resolve', { token: 'tok_fin_12345', tenant: 'quanta', role: 'finance', verified: false }, { orgSlug: 'quanta' }, true)
  caseB('B0-author-same-role-2hop', 'privilege_escalation', false, true, 'member')
  caseB('B1-pad-same-role-3hop', 'privilege_escalation', true, true, 'member')
  caseB('B1b-pad-same-role-3hop-bac', 'broken_access_control', true, true, 'member')
  caseB('B2-me-only-admin-2hop', 'privilege_escalation', true, false, 'admin')
  caseB('B3-TP-leak-admin-2hop', 'privilege_escalation', false, true, 'admin')
  caseB('B4-TP-pad-leak-admin-3hop', 'privilege_escalation', true, true, 'admin')
  caseB('B5-same-role-invitations-id-accept', 'bfla', false, true, 'member', '/invitations/i1/accept')
  // race actor-window binding on unrelated route
  const mk = (id: string, p: string, ts: number, extra: Record<string, unknown> = {}) => ({ exchangeId: id, timestampMs: ts, actorPersona: 'user_a', step: { ...ost({ id, arm: 'probe', method: 'POST', pathAndQuery: p }), route: p }, ...extra }) as never
  const m = new Map<string, never>([['cited', mk('cited', '/v1/wallet/transfer', 1100)], ['unrel', mk('unrel', '/v1/profile/avatar', 1150, { op: 'race' })], ['same', mk('same', '/v1/wallet/transfer', 1160, { op: 'race' })]])
  const recs = resolveEconomicActionRecords({ rawActRecs: ['cited', 'unrel', 'same'].map(id => ({ id, timestampMs: 1100 }) as never), entriesById: m, citedExchangeIds: ['cited'], baseRec: { id: 'b', timestampMs: 1000 } as never, finRec: { id: 'f', timestampMs: 1300 } as never })
  assert.deepEqual(recs.map(r => r.id), ['cited', 'same'], 'unrelated-route same-actor race burst must not bind as an economic action')
})
