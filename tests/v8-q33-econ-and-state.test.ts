/**
 * Queue #33 — Host Hydration of `HostSignedRecord`s & Logical State-Key Binding:
 *  1. `dispatchDefaultV8Oracle` hydrates `HostSignedRecord` fields inside `terminalImpact.oracleInput`
 *     from `HostSignedTranscript` via `toOracleRecord` (supporting string exchange IDs, `{ id }` /
 *     `{ exchangeId }` stubs, and `*ExchangeId` / `*ExchangeIds` alias fields across all 6
 *     `V8_ORACLE_FAMILIES`), plus fail-closed auto-hydration for `economic_conservation` when
 *     `baselineReadback`, `actions`, or `finalReadback` are omitted.
 *  2. `verifyStateTransitionBinding` resolves logical/namespaced state keys (e.g. `"perm:dual_member"`,
 *     `"org_b"`, `"cache:..."`) via canonical token matching + actor/session (or DAG-capability)
 *     continuity backed strictly by a clean-session denied ablation on `toHop`'s exact route family.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import type { ImpactStep } from '../src/server/proof-receipt.ts'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'q33-econ-and-state-signing-key-0123456789'

function signedEntry(
  exchangeId: string,
  opts: {
    arm: 'control' | 'probe'
    method: string
    pathAndQuery?: string
    route?: string
    status: number
    timestampMs: number
    actorPersona?: string | null
    actorRole?: 'viewer' | 'member' | 'admin' | 'owner' | null
    actorTenant?: string | null
    cleanSession?: boolean
    replayAttempt?: 'mode_a' | 'ablation_control' | 'primary'
    emittedCapabilities?: string[]
    consumedCapabilities?: string[]
    observedResponseDigests?: string[]
    entityId?: string
    json?: unknown
    body?: string
    evidenceRole?: string
  },
): HostTranscriptEntry {
  const actor = opts.actorPersona !== undefined ? opts.actorPersona : 'dual_member'
  const tenant = opts.actorTenant !== undefined ? opts.actorTenant : (actor ? 'org_a' : null)
  const role = opts.actorRole !== undefined ? opts.actorRole : (actor ? 'member' : null)
  const step: ImpactStep = {
    id: exchangeId,
    arm: opts.arm,
    method: opts.method,
    status: opts.status,
    actor: { handle: actor, role, tenant, auth: actor ? 'bearer' : 'unknown', sameSite: null },
    ...(opts.route !== undefined ? { route: opts.route } : opts.pathAndQuery ? { route: opts.pathAndQuery.split('?')[0]! } : {}),
    ...(opts.pathAndQuery !== undefined ? { pathAndQuery: opts.pathAndQuery } : {}),
    ...(opts.json !== undefined ? { json: opts.json } : {}),
    ...(opts.body !== undefined ? { body: opts.body } : {}),
    ...(opts.evidenceRole !== undefined ? { evidenceRole: opts.evidenceRole } : {}),
  }
  const rec: HostTranscriptEntry = {
    exchangeId,
    step,
    timestampMs: opts.timestampMs,
    actorPersona: actor,
    ...(opts.cleanSession !== undefined ? { cleanSession: opts.cleanSession } : { cleanSession: true }),
    ...(opts.replayAttempt ? { replayAttempt: opts.replayAttempt } : {}),
    ...(opts.emittedCapabilities ? { emittedCapabilities: opts.emittedCapabilities } : {}),
    ...(opts.consumedCapabilities ? { consumedCapabilities: opts.consumedCapabilities } : {}),
    ...(opts.observedResponseDigests ? { observedResponseDigests: opts.observedResponseDigests } : {}),
    ...(opts.entityId ? { entityId: opts.entityId } : {}),
  }
  return { ...rec, hostSignature: signHostRecord(rec, SIGNING_KEY) }
}

// ============================================================================
// 1. Blocker #1 — Host Hydration for `economic_conservation` & All Families
// ============================================================================

test('economic_conservation hydrates string exchange IDs, {id}/{exchangeId} stubs, and *ExchangeId aliases under signingKey', () => {
  const cap = 'cap:hop_1:refund_handle'
  const transcript: HostSignedTranscript = {
    entries: [
      signedEntry('gx-base', { arm: 'control', method: 'GET', pathAndQuery: '/v1/orders/ord-1', status: 200, timestampMs: 1000, json: { paid: 100, refunded: 0 } }),
      signedEntry('gx-r1', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/ord-1/refund', status: 200, timestampMs: 1100, emittedCapabilities: [cap], json: { refunded: 70 } }),
      signedEntry('gx-r2', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/ord-1/refund', status: 200, timestampMs: 1200, consumedCapabilities: [cap], json: { refunded: 70 } }),
      signedEntry('gx-final', { arm: 'control', method: 'GET', pathAndQuery: '/v1/orders/ord-1', status: 200, timestampMs: 1300, json: { paid: 100, refunded: 140 } }),
    ],
  }
  const makeReceipt = (oracleInput: Record<string, unknown>): CompositeProofReceipt => ({
    chainId: 'q33-econ-hydrate',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/ord-1/refund' }, exchangeIds: ['gx-r1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'First refund', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/ord-1/refund' }, exchangeIds: ['gx-r2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Second refund', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Over-refund violated order ledger conservation (140 > 100).',
      summary: 'Over-refund violated order ledger conservation (140 > 100).',
      terminalExchangeId: 'gx-r2',
      preChainControlExchangeIds: [],
      postChainReadbackExchangeIds: [],
      oracleInput,
    },
    replayMode: 'fresh_clean_replay',
  })

  // (a) Direct string exchange IDs
  const strPass = verifyCompositeReceipt(makeReceipt({
    equation: 'over_refund',
    baselineReadback: 'gx-base',
    actions: ['gx-r1', 'gx-r2'],
    finalReadback: 'gx-final',
    paidAmount: 100,
    refundedAmounts: [70, 70],
  }), transcript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(strPass.confirmed, true, strPass.reason)
  assert.equal(strPass.terminalOracleFamily, 'economic_conservation')

  // (b) Conserved ledger (hardened twin: 40 + 50 <= 100) MUST still fail closed!
  const conserved = verifyCompositeReceipt(makeReceipt({
    equation: 'over_refund',
    baselineReadback: 'gx-base',
    actions: ['gx-r1', 'gx-r2'],
    finalReadback: 'gx-final',
    paidAmount: 100,
    refundedAmounts: [40, 50],
  }), transcript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(conserved.confirmed, false)
  assert.equal(conserved.rejectedBy, 'v8_oracle_economic_conservation')
  assert.match(conserved.reason, /refund_ledger_conserved/)

  // (c) { id } / { exchangeId } stubs
  const stubPass = verifyCompositeReceipt(makeReceipt({
    equation: 'balance_minting',
    baselineReadback: { exchangeId: 'gx-base' },
    actions: [{ id: 'gx-r1' }, { exchangeId: 'gx-r2' }],
    finalReadback: { id: 'gx-final' },
    balancesBefore: { acct_a: 100 },
    balancesAfter: { acct_a: 180 },
    authorizedDeposits: 20,
  }), transcript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(stubPass.confirmed, true, stubPass.reason)

  // (d) *ExchangeId / *ExchangeIds aliases
  const aliasPass = verifyCompositeReceipt(makeReceipt({
    equation: 'ineligible_discount',
    baselineReadbackExchangeId: 'gx-base',
    actionExchangeIds: ['gx-r1', 'gx-r2'],
    finalReadbackExchangeId: 'gx-final',
    subtotalAmount: 40,
    requiredThreshold: 100,
    discountApplied: 25,
    finalTotalPaid: 15,
  }), transcript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(aliasPass.confirmed, true, aliasPass.reason)
})

test('economic_conservation auto-hydrates omitted baseline/actions/finalReadback from transcript and fails closed when any is missing', () => {
  const transcript: HostSignedTranscript = {
    entries: [
      signedEntry('gx-ctrl-403', { arm: 'control', method: 'POST', pathAndQuery: '/v1/orders/ord-2/refund', status: 403, timestampMs: 900, json: { error: 'denied' } }),
      signedEntry('gx-base-200', { arm: 'control', method: 'GET', pathAndQuery: '/v1/orders/ord-2', status: 200, timestampMs: 1000, json: { paid: 100, refunds: [] } }),
      signedEntry('gx-act-200', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/ord-2/refund', status: 200, timestampMs: 1200, json: { refunded: 150 } }),
      signedEntry('gx-stub-202', { arm: 'control', method: 'GET', pathAndQuery: '/v1/jobs/j-1', status: 200, timestampMs: 1250, json: { jobId: 'j-1', status: 'queued' } }),
      signedEntry('gx-final-200', { arm: 'control', method: 'GET', pathAndQuery: '/v1/orders/ord-2', status: 200, timestampMs: 1400, json: { paid: 100, refunded: 150, status: 'settled' } }),
      signedEntry('gx-late-base', { arm: 'control', method: 'GET', pathAndQuery: '/v1/orders/ord-2', status: 200, timestampMs: 1500, json: { paid: 100, refunded: 0 } }),
    ],
  }
  const makeReceipt = (pre: string[], post: string[], oracleInput?: Record<string, unknown>, hopEx = ['gx-act-200']): CompositeProofReceipt => ({
    chainId: 'q33-econ-auto',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/ord-2/refund' }, exchangeIds: hopEx, oobEventIds: [], browserTraceIds: [], claimedDelta: 'Issued over-refund', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      claimedImpact: 'Refund exceeded paid order amount via ledger race.',
      summary: 'Refund exceeded paid order amount via ledger race.',
      preChainControlExchangeIds: pre,
      postChainReadbackExchangeIds: post,
      ...(oracleInput ? { oracleInput } : {}),
    },
    replayMode: 'fresh_clean_replay',
  })

  // (a) Auto-hydrates baseline (skipping 403 -> gx-base-200), actions (gx-act-200), and finalReadback (skipping job stub -> gx-final-200)
  const autoPass = verifyCompositeReceipt(
    makeReceipt(['gx-ctrl-403', 'gx-base-200'], ['gx-stub-202', 'gx-final-200'], { equation: 'over_refund', paidAmount: 100, refundedAmounts: [150] }),
    transcript,
    { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY },
  )
  assert.equal(autoPass.confirmed, true, autoPass.reason)
  assert.equal(autoPass.terminalOracleFamily, 'economic_conservation')

  // (b) Missing 2xx baseline readback (only 403 or late readback after action) -> fails closed with missing_baseline_readback_record
  const noBase = verifyCompositeReceipt(
    makeReceipt(['gx-ctrl-403'], ['gx-final-200'], { equation: 'over_refund', paidAmount: 100, refundedAmounts: [150] }),
    transcript,
    { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY },
  )
  assert.equal(noBase.confirmed, false)
  assert.match(noBase.reason, /missing_baseline_readback_record/)

  const lateBase = verifyCompositeReceipt(
    makeReceipt(['gx-late-base'], ['gx-final-200'], { equation: 'over_refund', paidAmount: 100, refundedAmounts: [150] }),
    transcript,
    { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY },
  )
  assert.equal(lateBase.confirmed, false)
  assert.match(lateBase.reason, /missing_baseline_readback_record/)

  // (c) Post-chain readback only contains a job stub -> fails closed with missing_final_readback_record
  const stubOnlyFinal = verifyCompositeReceipt(
    makeReceipt(['gx-base-200'], ['gx-stub-202'], { equation: 'over_refund', paidAmount: 100, refundedAmounts: [150] }),
    transcript,
    { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY },
  )
  assert.equal(stubOnlyFinal.confirmed, false)
  assert.match(stubOnlyFinal.reason, /missing_final_readback_record/)

  // (d) Omitted oracleInput completely: surfaces missing_baseline_readback_record when baseline missing,
  //     and missing_economic_oracle_input when all 3 records exist (never forges equation parameters!)
  const omittedNoBase = verifyCompositeReceipt(
    makeReceipt(['gx-ctrl-403'], ['gx-final-200']),
    transcript,
    { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY },
  )
  assert.equal(omittedNoBase.confirmed, false)
  assert.equal(omittedNoBase.rejectedBy, 'v8_oracle_economic_conservation')
  assert.match(omittedNoBase.reason, /missing_baseline_readback_record/)
  assert.ok(omittedNoBase.missingEvidence?.includes('terminalImpact.oracleInput'))

  const omittedWithRecs = verifyCompositeReceipt(
    makeReceipt(['gx-base-200'], ['gx-final-200']),
    transcript,
    { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY },
  )
  assert.equal(omittedWithRecs.confirmed, false)
  assert.equal(omittedWithRecs.rejectedBy, 'v8_oracle_economic_conservation')
  assert.match(omittedWithRecs.reason, /missing_economic_oracle_input/)
  assert.ok(omittedWithRecs.missingEvidence?.includes('terminalImpact.oracleInput'))
})

test('hydration NEVER forges missing/tampered records or trusts client-spoofed stub fields', () => {
  const baseEntry = signedEntry('gx-base', { arm: 'control', method: 'GET', pathAndQuery: '/v1/orders/o1', status: 200, timestampMs: 1000, json: { paid: 100, refunded: 0 } })
  const failedAct = signedEntry('gx-act-403', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/o1/refund', status: 403, timestampMs: 1100, json: { error: 'blocked' } })
  const okAct = signedEntry('gx-act-200', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/o1/refund', status: 200, timestampMs: 1150, json: { refunded: 140 } })
  const finEntry = signedEntry('gx-final', { arm: 'control', method: 'GET', pathAndQuery: '/v1/orders/o1', status: 200, timestampMs: 1300, json: { paid: 100, refunded: 140 } })

  const transcript: HostSignedTranscript = { entries: [baseEntry, failedAct, okAct, finEntry] }
  const makeReceipt = (oracleInput: Record<string, unknown>): CompositeProofReceipt => ({
    chainId: 'q33-econ-tamper',
    terminalVulnClass: 'economic_conservation',
    hops: [{ hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/o1/refund' }, exchangeIds: ['gx-act-200'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Refund', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'hop_1', claimedImpact: 'Attempted forged economic claim.', summary: 'Attempted forged economic claim.', preChainControlExchangeIds: ['gx-base'], postChainReadbackExchangeIds: ['gx-final'], oracleInput },
    replayMode: 'fresh_clean_replay',
  })

  // Missing explicit ID must NOT fall back to auto-hydration or forge
  const missingId = verifyCompositeReceipt(makeReceipt({
    equation: 'over_refund', baselineReadback: 'gx-nonexistent', actions: ['gx-act-200'], finalReadback: 'gx-final', paidAmount: 100, refundedAmounts: [140],
  }), transcript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(missingId.confirmed, false)
  assert.match(missingId.reason, /missing_baseline_readback_record/)

  // Missing element inside actions array must NOT be silently dropped
  const missingActItem = verifyCompositeReceipt(makeReceipt({
    equation: 'over_refund', baselineReadback: 'gx-base', actions: ['gx-act-200', 'gx-ghost'], finalReadback: 'gx-final', paidAmount: 100, refundedAmounts: [140],
  }), transcript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(missingActItem.confirmed, false)
  assert.match(missingActItem.reason, /missing_action_1_record/)

  // Client stub claiming status: 200 for a host-recorded 403 action MUST hydrate real 403 status -> fail closed
  const spoofedStub = verifyCompositeReceipt(makeReceipt({
    equation: 'over_refund',
    baselineReadback: 'gx-base',
    actions: [{ exchangeId: 'gx-act-403', status: 200, timestampMs: 1150 }],
    finalReadback: 'gx-final',
    paidAmount: 100,
    refundedAmounts: [140],
  }), transcript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(spoofedStub.confirmed, false)
  assert.match(spoofedStub.reason, /no_successful_action/)

  // Tampered transcript entry referenced ONLY in oracleInput (not in preChainControlExchangeIds) fails signature check!
  const tamperedTranscript: HostSignedTranscript = {
    entries: [{ ...baseEntry, step: { ...baseEntry.step, status: 201 } }, okAct, finEntry],
  }
  const tamperedReceipt = makeReceipt({
    equation: 'over_refund', baselineReadback: 'gx-base', actions: ['gx-act-200'], finalReadback: 'gx-final', paidAmount: 100, refundedAmounts: [140],
  })
  tamperedReceipt.terminalImpact.preChainControlExchangeIds = []
  const tamperedRes = verifyCompositeReceipt(tamperedReceipt, tamperedTranscript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(tamperedRes.confirmed, false)
  assert.match(tamperedRes.reason, /invalid_baseline_readback_signature/)
})

test('host hydration works across dual_tenant_abac, temporal_revocation, cryptographic_scope_replay, parser_cache_differential, and cross_surface_pivot', () => {
  const cap = 'cap:hop_1:shared_tok'
  const sigDig = sha256Hex('valid-sig')
  const badDig = sha256Hex('tampered-sig')
  const transcript: HostSignedTranscript = {
    entries: [
      signedEntry('gx-ctrl', { arm: 'control', method: 'GET', pathAndQuery: '/v1/orgs/org_b/records', status: 403, timestampMs: 900, observedResponseDigests: [badDig], json: { error: 'denied' } }),
      signedEntry('gx-prime', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/permissions', status: 200, timestampMs: 1000, emittedCapabilities: [cap], observedResponseDigests: [sigDig], json: { role: 'admin', tenantId: 'org_a' } }),
      signedEntry('gx-bled', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/orgs/org_b/records', status: 200, timestampMs: 1100, consumedCapabilities: [cap], observedResponseDigests: [sigDig], json: { tenantId: 'org_b', records: [{ id: 'r1', balance: 9000 }] } }),
      signedEntry('gx-rev', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/tokens/revoke', status: 200, timestampMs: 1000, emittedCapabilities: [cap], json: { revoked: true } }),
      signedEntry('gx-prim-deny', { arm: 'control', method: 'GET', pathAndQuery: '/v1/rest/profile', status: 401, timestampMs: 1050, consumedCapabilities: [cap], json: { error: 'revoked' } }),
      signedEntry('gx-sec-ok', { arm: 'probe', method: 'POST', pathAndQuery: '/graphql', status: 200, timestampMs: 1150, consumedCapabilities: [cap], json: { data: { secret: 's-1', balance: 400 } } }),
    ],
  }

  // 1. dual_tenant_abac via string exchange IDs
  const dualRes = verifyCompositeReceipt({
    chainId: 'q33-dual-hydrate',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/permissions' }, exchangeIds: ['gx-prime'], producedCapabilities: [cap], claimedDelta: 'Primed' },
      { hopId: 'h2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/orgs/org_b/records' }, exchangeIds: ['gx-bled'], consumedCapabilities: [cap], claimedDelta: 'Read org_b' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'h2',
      summary: 'Dual-org cache bleed exposed org_b confidential records.',
      terminalExchangeId: 'gx-bled',
      preChainControlExchangeIds: ['gx-ctrl'],
      oracleInput: {
        mode: 'dual_org_cache_bleed',
        actor: { actorId: 'dual_member', rolesByTenant: { org_a: 'admin', org_b: 'viewer' } },
        primeTenantId: 'org_a',
        targetTenantId: 'org_b',
        baselineDeniedControl: 'gx-ctrl',
        primeAction: 'gx-prime',
        bledAccess: 'gx-bled',
      },
    },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(dualRes.confirmed, true, dualRes.reason)

  // 2. temporal_revocation via *ExchangeId aliases
  const tempRes = verifyCompositeReceipt({
    chainId: 'q33-temp-hydrate',
    terminalVulnClass: 'temporal_revocation',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/tokens/revoke' }, exchangeIds: ['gx-rev'], producedCapabilities: [cap], claimedDelta: 'Revoked token' },
      { hopId: 'h2', surface: 'graphql', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/graphql' }, exchangeIds: ['gx-sec-ok'], consumedCapabilities: [cap], claimedDelta: 'Used revoked token on GraphQL' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'h2',
      summary: 'Revoked token remained valid on secondary GraphQL surface.',
      terminalExchangeId: 'gx-sec-ok',
      preChainControlExchangeIds: ['gx-prim-deny'],
      oracleInput: {
        credentialKind: 'token',
        credentialHandle: cap,
        primarySurface: 'http',
        secondarySurface: 'graphql',
        revocationEventExchangeId: 'gx-rev',
        primaryDeniedCheckExchangeId: 'gx-prim-deny',
        secondarySuccessExchangeId: 'gx-sec-ok',
      },
    },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(tempRes.confirmed, false, 'preChainControl route family differs from /graphql unless control is on /graphql')
  // Confirm when clean control is on /graphql (proving temporal_revocation oracle itself hydrated and satisfied!)
  const gxGqlDeny = signedEntry('gx-gql-deny', { arm: 'control', method: 'POST', pathAndQuery: '/graphql', status: 403, timestampMs: 850, json: { error: 'denied' } })
  const tempPass = verifyCompositeReceipt({
    chainId: 'q33-temp-hydrate-ok',
    terminalVulnClass: 'temporal_revocation',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/tokens/revoke' }, exchangeIds: ['gx-rev'], producedCapabilities: [cap], claimedDelta: 'Revoked token' },
      { hopId: 'h2', surface: 'graphql', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/graphql' }, exchangeIds: ['gx-sec-ok'], consumedCapabilities: [cap], claimedDelta: 'Used revoked token on GraphQL' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'h2',
      summary: 'Revoked token remained valid on secondary GraphQL surface.',
      terminalExchangeId: 'gx-sec-ok',
      preChainControlExchangeIds: ['gx-gql-deny'],
      oracleInput: {
        credentialKind: 'token',
        credentialHandle: cap,
        primarySurface: 'http',
        secondarySurface: 'graphql',
        revocationEventExchangeId: 'gx-rev',
        primaryDeniedCheckExchangeId: 'gx-prim-deny',
        secondarySuccessExchangeId: 'gx-sec-ok',
      },
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [...transcript.entries!, gxGqlDeny] }, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(tempPass.confirmed, true, tempPass.reason)

  // 3. cryptographic_scope_replay via { exchangeId } stubs
  const cryptoRes = verifyCompositeReceipt({
    chainId: 'q33-crypto-hydrate',
    terminalVulnClass: 'cryptographic_scope_replay',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/permissions' }, exchangeIds: ['gx-prime'], producedCapabilities: [cap], claimedDelta: 'Issued signed token' },
      { hopId: 'h2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/orgs/org_b/records' }, exchangeIds: ['gx-bled'], consumedCapabilities: [cap], claimedDelta: 'Replayed across scope' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'h2',
      summary: 'Valid signature from org_a replayed to access org_b records.',
      terminalExchangeId: 'gx-bled',
      preChainControlExchangeIds: ['gx-ctrl'],
      oracleInput: {
        tamperedSignatureControl: { exchangeId: 'gx-ctrl' },
        sourceValidIssuance: { exchangeId: 'gx-prime' },
        replayedAcceptance: { exchangeId: 'gx-bled' },
        sourceTenant: 'org_a',
        sourceScope: 'permissions:read',
        targetTenant: 'org_b',
        targetScope: 'records:read',
      },
    },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(cryptoRes.confirmed, true, cryptoRes.reason)

  // 4. parser_cache_differential via *ExchangeId aliases
  const parserRes = verifyCompositeReceipt({
    chainId: 'q33-parser-hydrate',
    terminalVulnClass: 'parser_cache_differential',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/permissions' }, exchangeIds: ['gx-prime'], producedCapabilities: [cap], claimedDelta: 'Primed' },
      { hopId: 'h2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/orgs/org_b/records' }, exchangeIds: ['gx-bled'], consumedCapabilities: [cap], claimedDelta: 'Differential bypass' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'h2',
      summary: 'Header normalization differential exposed org_b records.',
      terminalExchangeId: 'gx-bled',
      preChainControlExchangeIds: ['gx-ctrl'],
      oracleInput: {
        mode: 'parser_differential',
        differentialKind: 'header_normalization',
        differentialFeature: 'x-tenant-header',
        canonicalValue: 'org_a',
        variantValue: 'org_a, org_b',
        impactKind: 'read',
        cleanControlExchangeId: 'gx-ctrl',
        differentialProbeExchangeId: 'gx-bled',
      },
    },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(parserRes.confirmed, true, parserRes.reason)

  // 5. cross_surface_pivot via nested hop exchangeId hydration
  const pivotRes = verifyCompositeReceipt({
    chainId: 'q33-pivot-hydrate',
    terminalVulnClass: 'cross_surface_pivot',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/permissions' }, exchangeIds: ['gx-prime'], producedCapabilities: [cap], claimedDelta: 'HTTP emit' },
      { hopId: 'h2', surface: 'graphql', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/graphql' }, exchangeIds: ['gx-sec-ok'], consumedCapabilities: [cap], claimedDelta: 'GraphQL pivot' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'h2',
      summary: 'HTTP-to-GraphQL cross-surface pivot exposed privileged secret.',
      terminalExchangeId: 'gx-sec-ok',
      preChainControlExchangeIds: ['gx-gql-deny'],
      oracleInput: {
        attackerOriginPersona: { actorId: 'dual_member', role: 'member', tenantId: 'org_a', isPrivilegedPreSeeded: false },
        preChainControlExchangeId: 'gx-gql-deny',
        hops: [
          { surface: 'http', role: 'trigger_write', exchangeId: 'gx-prime', emittedArtifactDigest: cap },
          { surface: 'graphql', role: 'terminal_impact', exchangeId: 'gx-sec-ok', bindingKind: 'value_binding', consumedArtifactDigest: cap },
        ],
        terminalImpact: { kind: 'privileged_read', verified: true, impactDigest: sha256Hex('secret-s-1') },
      },
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [...transcript.entries!, gxGqlDeny] }, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(pivotRes.confirmed, true, pivotRes.reason)
})

// ============================================================================
// 2. Blocker #2 — `state_transition_binding` on Logical State Keys
// ============================================================================

test('state_transition_binding accepts logical state keys ("perm:dual_member", "org_b", "cache:slot") with strict exact-route clean-session denied ablation', () => {
  // (a) Namespaced logical key "perm:dual_member" absent verbatim from both hops
  const permTranscript: HostSignedTranscript = {
    entries: [
      signedEntry('gx-ab', { arm: 'control', method: 'GET', pathAndQuery: '/v1/orgs/org_b/secrets', status: 403, timestampMs: 800, actorPersona: 'dual_member', replayAttempt: 'ablation_control', json: { error: 'forbidden' } }),
      signedEntry('gx-prime', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/permissions', status: 200, timestampMs: 1000, actorPersona: 'dual_member', json: { role: 'admin', cached: true } }),
      signedEntry('gx-bled', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/orgs/org_b/secrets', status: 200, timestampMs: 1200, actorPersona: 'dual_member', json: { tenantId: 'org_b', records: [{ id: 'sec-1', apiKey: 'k-999' }] } }),
    ],
  }
  const permReceipt = (entityId: string): CompositeProofReceipt => ({
    chainId: `q33-stb-${entityId.replace(/[^a-z0-9]/gi, '-')}`,
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/permissions' }, exchangeIds: ['gx-prime'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed permission cache on own tenant', producedCapabilities: [], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/orgs/org_b/secrets' }, exchangeIds: ['gx-bled'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Accessed org_b secrets using primed permission cache', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [{ kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2', entityId, ablationExchangeIds: ['gx-ab'] }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Permission cache bleed exposed org_b API secrets.',
      summary: 'Permission cache bleed exposed org_b API secrets.',
      terminalExchangeId: 'gx-bled',
      preChainControlExchangeIds: ['gx-ab'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  })

  for (const key of ['perm:dual_member', 'org_b', 'cache:perm_slot']) {
    const res = verifyCompositeReceipt(permReceipt(key), permTranscript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
    assert.equal(res.confirmed, true, `key=${key}: ${res.reason}`)
    assert.equal(res.verifiedEdges[0]?.verified, true)
    assert.equal(res.verifiedEdges[0]?.evidence?.bindingMode, 'logical_key_ablation')
  }

  // (b) Unlabeled clean-session 403 BEFORE fromHop on exact route family also passes
  const unlabeledBeforeTranscript: HostSignedTranscript = {
    entries: [
      signedEntry('gx-ab', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/orgs/org_b/secrets', status: 403, timestampMs: 800, actorPersona: 'dual_member', cleanSession: true, json: { error: 'forbidden' } }),
      permTranscript.entries![1]!,
      permTranscript.entries![2]!,
    ],
  }
  const unlabRes = verifyCompositeReceipt(permReceipt('perm:dual_member'), unlabeledBeforeTranscript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(unlabRes.verifiedEdges[0]?.verified, true, unlabRes.reason)

  // (c) DAG-derived capability continuity on toHop (actorPersona: null) with logical state key passes
  const cap = 'cap:hop_0:minted_sess'
  const dagCapTranscript: HostSignedTranscript = {
    entries: [
      signedEntry('gx-0', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/session', status: 200, timestampMs: 700, actorPersona: 'dual_member', emittedCapabilities: [cap], json: { session: 's1' } }),
      signedEntry('gx-ab', { arm: 'control', method: 'GET', pathAndQuery: '/v1/orgs/org_b/secrets', status: 403, timestampMs: 800, actorPersona: 'dual_member', replayAttempt: 'ablation_control' }),
      signedEntry('gx-prime', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/permissions', status: 200, timestampMs: 1000, actorPersona: 'dual_member', consumedCapabilities: [cap], json: { cached: true } }),
      signedEntry('gx-bled', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/orgs/org_b/secrets', status: 200, timestampMs: 1200, actorPersona: null, consumedCapabilities: [cap], json: { tenantId: 'org_b', records: [{ id: 'sec-1', apiKey: 'k-999' }] } }),
    ],
  }
  const dagCapRes = verifyCompositeReceipt({
    chainId: 'q33-stb-dag-cap',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_0', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/session' }, exchangeIds: ['gx-0'], producedCapabilities: [cap], claimedDelta: 'Minted session' },
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/permissions' }, exchangeIds: ['gx-prime'], consumedCapabilities: [cap], claimedDelta: 'Primed cache' },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/orgs/org_b/secrets' }, exchangeIds: ['gx-bled'], consumedCapabilities: [cap], claimedDelta: 'Read secrets' },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'hop_0', toHopId: 'hop_1', capabilityHandle: cap },
      { kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2', entityId: 'cache:slot_9', ablationExchangeIds: ['gx-ab'] },
    ],
    terminalImpact: { terminalHopId: 'hop_2', summary: 'Primed session read org_b secrets.', terminalExchangeId: 'gx-bled', preChainControlExchangeIds: ['gx-ab'] },
    replayMode: 'fresh_clean_replay',
  }, dagCapTranscript, { attackerPersonas: ['dual_member'], signingKey: SIGNING_KEY })
  assert.equal(dagCapRes.confirmed, true, dagCapRes.reason)
})

test('state_transition_binding logical-key fallback HARD-REJECTS dirty/2xx/5xx/wrong-route/wrong-actor/non-monotonic/actor-discontinuity', () => {
  const buildAndVerify = (overrides: {
    prime?: Partial<Parameters<typeof signedEntry>[1]>
    bled?: Partial<Parameters<typeof signedEntry>[1]>
    ab?: Partial<Parameters<typeof signedEntry>[1]>
    entityId?: string
    attackers?: string[]
  }) => {
    const transcript: HostSignedTranscript = {
      entries: [
        signedEntry('gx-ab', {
          arm: 'control', method: 'GET', pathAndQuery: '/v1/orgs/org_b/secrets', status: 403, timestampMs: 800,
          actorPersona: 'dual_member', cleanSession: true, replayAttempt: 'ablation_control', ...overrides.ab,
        }),
        signedEntry('gx-prime', {
          arm: 'probe', method: 'GET', pathAndQuery: '/v1/permissions', status: 200, timestampMs: 1000,
          actorPersona: 'dual_member', json: { cached: true }, ...overrides.prime,
        }),
        signedEntry('gx-bled', {
          arm: 'probe', method: 'GET', pathAndQuery: '/v1/orgs/org_b/secrets', status: 200, timestampMs: 1200,
          actorPersona: 'dual_member', json: { tenantId: 'org_b', records: [{ id: 's1', secret: 'x' }] }, ...overrides.bled,
        }),
      ],
    }
    return verifyCompositeReceipt({
      chainId: 'q33-stb-neg',
      terminalVulnClass: 'business_logic',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/permissions' }, exchangeIds: ['gx-prime'], claimedDelta: 'Prime' },
        { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/orgs/org_b/secrets' }, exchangeIds: ['gx-bled'], claimedDelta: 'Read' },
      ],
      causalEdges: [{ kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2', entityId: overrides.entityId ?? 'perm:dual_member', ablationExchangeIds: ['gx-ab'] }],
      terminalImpact: { terminalHopId: 'hop_2', summary: 'Logical state-key binding negative test.' },
      replayMode: 'fresh_clean_replay',
    }, transcript, { attackerPersonas: overrides.attackers ?? ['dual_member', 'other_member'], signingKey: SIGNING_KEY })
  }

  // 1. Dirty cleanSession=false ablation -> REJECT
  const dirty = buildAndVerify({ ab: { cleanSession: false } })
  assert.equal(dirty.confirmed, false)
  assert.equal(dirty.failedStage, 'edge_binding')
  assert.match(dirty.reason, /cleanSession=false/)

  // 2. 2xx ablation (even with evidenceRole='invariant_preserved'!) -> REJECT on logical fallback
  const ok200 = buildAndVerify({ ab: { status: 200, evidenceRole: 'invariant_preserved' } })
  assert.equal(ok200.confirmed, false)
  assert.equal(ok200.failedStage, 'edge_binding')
  assert.match(ok200.reason, /status=2xx/)

  // 3. 5xx ablation -> REJECT
  const err500 = buildAndVerify({ ab: { status: 502 } })
  assert.equal(err500.confirmed, false)
  assert.equal(err500.failedStage, 'edge_binding')
  assert.match(err500.reason, /status=5xx/)

  // 4. Wrong route family ablation (EVEN IF ab.entityId matches edge.entityId!) -> REJECT
  const wrongRoute = buildAndVerify({ ab: { pathAndQuery: '/v1/orgs/org_b/billing', entityId: 'perm:dual_member' } })
  assert.equal(wrongRoute.confirmed, false)
  assert.equal(wrongRoute.failedStage, 'edge_binding')
  assert.match(wrongRoute.reason, /route_family_mismatch/)

  // 5. Wrong actor ablation (different persona OR anonymous null 401 for authenticated toHop) -> REJECT
  const wrongActor = buildAndVerify({ ab: { actorPersona: 'other_member' } })
  assert.equal(wrongActor.confirmed, false)
  assert.equal(wrongActor.failedStage, 'edge_binding')
  assert.match(wrongActor.reason, /actor_mismatch/)

  const anonAblation = buildAndVerify({ ab: { actorPersona: null, status: 401 } })
  assert.equal(anonAblation.confirmed, false)
  assert.equal(anonAblation.failedStage, 'edge_binding')
  assert.match(anonAblation.reason, /actor_mismatch/)

  // 6. Non-monotonic timestamps (t_from > t_to) -> REJECT
  const nonMono = buildAndVerify({ prime: { timestampMs: 1500 }, bled: { timestampMs: 1200 } })
  assert.equal(nonMono.confirmed, false)
  assert.equal(nonMono.failedStage, 'edge_binding')
  assert.match(nonMono.reason, /monotonic/)

  // 7. Actor discontinuity between fromHop and toHop (different personas, no DAG cap) -> REJECT
  const disc = buildAndVerify({ prime: { actorPersona: 'other_member' }, bled: { actorPersona: 'dual_member' } })
  assert.equal(disc.confirmed, false)
  assert.equal(disc.failedStage, 'edge_binding')
  assert.match(disc.reason, /actor_discontinuity/)

  // 8. Unlabeled ablation AFTER fromHop -> REJECT
  const unlabAfter = buildAndVerify({ ab: { arm: 'probe', replayAttempt: undefined, timestampMs: 1500 } })
  assert.equal(unlabAfter.confirmed, false)
  assert.equal(unlabAfter.failedStage, 'edge_binding')
  assert.match(unlabAfter.reason, /unlabeled_control/)

  // 9. fromHop failing (403, 0 succeeding probes) -> REJECT
  const fromFail = buildAndVerify({ prime: { status: 403 } })
  assert.equal(fromFail.confirmed, false)
  assert.equal(fromFail.failedStage, 'edge_binding')
  assert.match(fromFail.reason, /fromOk=0: exchanges=1, 2xx=0/)
})

// ============================================================================
// 3. LOC Ceilings & Anti-Contamination Gate
// ============================================================================

test('LOC ceilings hold (composite-receipt <= 750, v8-oracle-families <= 750) with zero benchmark literals', () => {
  const loc = (rel: string) => readFileSync(join(REPO_ROOT, rel), 'utf8').trimEnd().split('\n').length
  assert.ok(loc('src/server/composite-receipt.ts') <= 750, `composite-receipt.ts=${loc('src/server/composite-receipt.ts')}`)
  assert.ok(loc('src/server/v8-oracle-families.ts') <= 750, `v8-oracle-families.ts=${loc('src/server/v8-oracle-families.ts')}`)
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, JSON.stringify(scan.hits))
})
