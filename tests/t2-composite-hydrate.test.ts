/**
 * Tier-2 Security Audit Regression Suite — C-4, H-11, H-12, and H-32 (verify-claims half).
 *
 * Verifies:
 *   - C-4: `hydrateV8OracleInput` allowlists only safe structural fields (no raw spread), derives
 *          all operands/digests/booleans strictly from host transcript exchanges, and
 *          `economic_conservation` never bypasses stub / own-tenant / strict gates.
 *   - H-11: I6 attacker provenance fails closed for privileged roles/handles (`admin`/`owner`) even
 *           when `attackerPersonas` is omitted, blocks control-arm capability smuggling, and never
 *           hard-codes `isPrivilegedPreSeeded: false` in `cross_surface_pivot`.
 *   - H-12: I7 fail-closed terminal gate rejects composite receipts with no `oracleFamily` on a
 *           bare 2xx (including `ssrf`, `business_logic`, empty-body 2xx, and 404 on a different ID).
 *   - H-32: `verify-claims.ts` rejects ReDoS regexes (`(a+)+$`, `(a|aa)+$`, >256 chars, >16 alts,
 *           backrefs, lookarounds, stacked quantifiers) in `< 5ms` and caps matched haystacks.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { performance } from 'node:perf_hooks'
import test from 'node:test'

import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import { hydrateV8OracleInput, type HydratableTranscriptIndex } from '../src/server/v8-oracle-hydrate.ts'
import { TranscriptStore, compileSafeClaimRegex, evaluateClaim } from '../src/server/verify-claims.ts'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 't2-composite-hydrate-signing-key-9012345678'

function makeStep(partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? { handle: 'member_alpha', role: 'member', tenant: 'org-alpha', auth: 'bearer', sameSite: null },
    ...(partial.route !== undefined ? { route: partial.route } : partial.pathAndQuery ? { route: partial.pathAndQuery.split('?')[0]! } : {}),
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
    step,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...base, hostSignature: signHostRecord(base, SIGNING_KEY) }
}

// ============================================================================
// C-4: Host-only hydration (no rawInput spread) & economic_conservation gates
// ============================================================================

test('C-4: hydrateV8OracleInput strips forged model operands/booleans and cannot spoof any v8 oracle family', () => {
  // 1. Forged economic_conservation operands on benign/conserved host transcript MUST fail closed
  const benignBase = signedEntry('gx-b-base', makeStep({
    id: 'gx-b-base', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/api/wallet/w-1', json: { walletId: 'w-1', paidAmount: 100, refundedTotal: 0, balance: 500 },
  }), { timestampMs: 1000 })
  const benignAct = signedEntry('gx-b-act', makeStep({
    id: 'gx-b-act', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/wallet/w-1/refund', json: { refunded: 40, credited: 100 },
  }), { timestampMs: 1100 })
  const benignFinal = signedEntry('gx-b-final', makeStep({
    id: 'gx-b-final', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/api/wallet/w-1', json: { walletId: 'w-1', paidAmount: 100, refundedTotal: 40, balance: 600 },
    evidenceRole: 'post_chain_readback',
  }), { timestampMs: 1200 })

  const idx: HydratableTranscriptIndex = {
    entriesById: new Map([
      [benignBase.exchangeId, benignBase],
      [benignAct.exchangeId, benignAct],
      [benignFinal.exchangeId, benignFinal],
    ]),
  }

  // Raw spread check: unknown forged keys & booleans MUST NOT survive hydration
  const hydratedOverRefund = hydrateV8OracleInput('economic_conservation', {
    equation: 'over_refund',
    baselineReadback: 'gx-b-base',
    actions: ['gx-b-act'],
    finalReadback: 'gx-b-final',
    paidAmount: 1, // forged lower paidAmount
    refundedAmounts: [999, 999], // forged inflated refunds
    spoofedFlag: true,
    elevatedRoleGranted: true,
  }, idx, 'sig')
  assert.equal('spoofedFlag' in hydratedOverRefund, false, 'unknown rawInput fields must be stripped')
  assert.equal('elevatedRoleGranted' in hydratedOverRefund, false, 'foreign boolean flags must be stripped')
  assert.equal(hydratedOverRefund.paidAmount, 100, 'paidAmount must come from host transcript, not forged lower value')
  assert.deepEqual(hydratedOverRefund.refundedAmounts, [40], 'refundedAmounts must come from host transcript, not forged [999, 999]')

  const econForgedRefund = verifyCompositeReceipt({
    chainId: 't2-c4-forged-over-refund',
    terminalVulnClass: 'economic_conservation',
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/wallet/w-1/refund' },
      exchangeIds: ['gx-b-act'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Attempted forged over-refund', producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      summary: 'Attempted to spoof over-refund on conserved host ledger.',
      terminalExchangeId: 'gx-b-act',
      preChainControlExchangeIds: ['gx-b-base'],
      postChainReadbackExchangeIds: ['gx-b-final'],
      oracleFamily: 'economic_conservation',
      oracleInput: {
        equation: 'over_refund',
        baselineReadback: 'gx-b-base',
        actions: ['gx-b-act'],
        finalReadback: 'gx-b-final',
        paidAmount: 1,
        refundedAmounts: [999],
      },
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [benignBase, benignAct, benignFinal] }, { attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY })
  assert.equal(econForgedRefund.confirmed, false, 'forged over_refund operands must fail closed')
  assert.match(econForgedRefund.reason, /refund_ledger_conserved/)

  // Forged balance_minting (model lies balancesAfter=9999 & authorizedDeposits=0 & authorizedWithdrawals=500)
  const econForgedMint = verifyCompositeReceipt({
    chainId: 't2-c4-forged-balance-mint',
    terminalVulnClass: 'economic_conservation',
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/wallet/w-1/refund' },
      exchangeIds: ['gx-b-act'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Attempted forged balance minting', producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      summary: 'Attempted to spoof balance minting via forged rawInput balances.',
      terminalExchangeId: 'gx-b-act',
      preChainControlExchangeIds: ['gx-b-base'],
      postChainReadbackExchangeIds: ['gx-b-final'],
      oracleFamily: 'economic_conservation',
      oracleInput: {
        equation: 'balance_minting',
        baselineReadback: 'gx-b-base',
        actions: ['gx-b-act'],
        finalReadback: 'gx-b-final',
        balancesBefore: { w: 100 },
        balancesAfter: { w: 9999 },
        authorizedDeposits: 0,
        authorizedWithdrawals: 500,
      },
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [benignBase, benignAct, benignFinal] }, { attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY })
  assert.equal(econForgedMint.confirmed, false, 'forged balance_minting operands must fail closed')
  assert.match(econForgedMint.reason, /balance_ledger_conserved/)

  // 2. Forged cacheHitObserved: true & victimArtifactDigest on parser_cache_differential MUST fail closed
  const ctrl403 = signedEntry('gx-pc-c', makeStep({
    id: 'gx-pc-c', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/reports/latest', json: { error: 'denied' },
  }), { timestampMs: 800 })
  const primeVictim = signedEntry('gx-pc-v', makeStep({
    id: 'gx-pc-v', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/reports/latest',
    actor: { handle: 'member_beta', role: 'member', tenant: 'org-beta', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org-beta', report: 'victim-secret-data' },
  }), { timestampMs: 1000, actorPersona: 'member_beta' })
  const probeNoCache = signedEntry('gx-pc-p', makeStep({
    id: 'gx-pc-p', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/reports/latest',
    responseHeaders: {}, // NO cache hit header!
    json: { tenantId: 'org-beta', report: 'different-public-data' },
  }), { timestampMs: 1200 })

  const forgedCacheRes = verifyCompositeReceipt({
    chainId: 't2-c4-forged-cache',
    terminalVulnClass: 'parser_cache_differential',
    hops: [{
      hopId: 'hop_1', surface: 'cdn',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/reports/latest' },
      exchangeIds: ['gx-pc-p'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Spoofed cache bleed', producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      summary: 'Attempted to spoof cache hit and victim digest via rawInput.',
      terminalExchangeId: 'gx-pc-p',
      preChainControlExchangeIds: ['gx-pc-c'],
      postChainReadbackExchangeIds: [],
      oracleFamily: 'parser_cache_differential',
      oracleInput: {
        mode: 'cache_primed',
        cacheKey: 'GET:/api/reports/latest',
        victimArtifactDigest: sha256Hex(JSON.stringify(probeNoCache.step.json)),
        cleanControl: 'gx-pc-c',
        victimOrPrimeRequest: 'gx-pc-v',
        attackerProbe: 'gx-pc-p',
        cacheHitObserved: true,
        isolatedControl: true,
      },
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrl403, primeVictim, probeNoCache] }, { attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY })
  assert.equal(forgedCacheRes.confirmed, false, 'forged cacheHitObserved / victimArtifactDigest must fail closed')
  assert.match(forgedCacheRes.reason, /no_cache_hit_evidence/)

  // 3. Forged signature digests & persistedImpact: true on cryptographic_scope_replay MUST fail closed
  const fakeSigCtrl = signedEntry('gx-cs-c', makeStep({
    id: 'gx-cs-c', arm: 'control', method: 'POST', status: 403, pathAndQuery: '/api/hooks/run', json: { error: 'bad_sig' },
  }), { timestampMs: 800 })
  const fakeIssue = signedEntry('gx-cs-i', makeStep({
    id: 'gx-cs-i', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/hooks/info', json: { info: 'hello' },
  }), { timestampMs: 1000 })
  const fakeReplay = signedEntry('gx-cs-r', makeStep({
    id: 'gx-cs-r', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/hooks/run', json: { tenantId: 'org-beta', ok: true, id: 'run-1' },
  }), { timestampMs: 1200 })

  const forgedCryptoRes = verifyCompositeReceipt({
    chainId: 't2-c4-forged-crypto',
    terminalVulnClass: 'cryptographic_scope_replay',
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/hooks/run' },
      exchangeIds: ['gx-cs-r'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Spoofed crypto scope replay', producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      summary: 'Attempted to spoof signature digests and persistedImpact via rawInput.',
      terminalExchangeId: 'gx-cs-r',
      preChainControlExchangeIds: ['gx-cs-c'],
      postChainReadbackExchangeIds: [],
      oracleFamily: 'cryptographic_scope_replay',
      oracleInput: {
        tamperedSignatureControl: 'gx-cs-c',
        sourceValidIssuance: 'gx-cs-i',
        replayedAcceptance: 'gx-cs-r',
        sourceTenant: 'org-alpha',
        sourceScope: 'read:a',
        targetTenant: 'org-beta',
        targetScope: 'write:b',
        tamperedSignatureDigest: sha256Hex('forged-bad'),
        signatureDigest: sha256Hex('forged-good'),
        replayedSignatureDigest: sha256Hex('forged-good'),
        persistedImpact: true,
      },
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [fakeSigCtrl, fakeIssue, fakeReplay] }, { attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY })
  assert.equal(forgedCryptoRes.confirmed, false, 'forged cryptographic_scope_replay digests must fail closed')
  assert.match(forgedCryptoRes.reason, /replayed_signature_digest_mismatch/)

  // 4. Forged observedOwnerTenantId on dual_tenant_abac cross_org_transfer MUST fail closed
  const dtCtrl = signedEntry('gx-dt-c', makeStep({
    id: 'gx-dt-c', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/assets/a-9', json: { error: 'denied' },
  }), { timestampMs: 800 })
  const dtXfer = signedEntry('gx-dt-x', makeStep({
    id: 'gx-dt-x', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/assets/a-9/transfer', json: { accepted: true },
  }), { timestampMs: 1000 })
  const dtRb = signedEntry('gx-dt-rb', makeStep({
    id: 'gx-dt-rb', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/assets/a-9',
    json: { id: 'a-9', ownerTenantId: 'org-beta', note: 'still-owned-by-beta' },
  }), { timestampMs: 1200 })

  const forgedDtRes = verifyCompositeReceipt({
    chainId: 't2-c4-forged-dual-tenant',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/assets/a-9' },
      exchangeIds: ['gx-dt-x', 'gx-dt-rb'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Spoofed cross-org transfer', producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      summary: 'Attempted to spoof observedOwnerTenantId via rawInput.',
      terminalExchangeId: 'gx-dt-rb',
      preChainControlExchangeIds: ['gx-dt-c'],
      postChainReadbackExchangeIds: ['gx-dt-rb'],
      oracleFamily: 'dual_tenant_abac',
      oracleInput: {
        mode: 'cross_org_transfer',
        actor: { actorId: 'member_alpha', rolesByTenant: { 'org-alpha': 'admin', 'org-beta': 'viewer' } },
        sourceTenantId: 'org-beta',
        destTenantId: 'org-alpha',
        entityId: 'a-9',
        observedOwnerTenantId: 'org-alpha', // forged: host readback says org-beta!
        sourceControlDenied: 'gx-dt-c',
        transferRecord: 'gx-dt-x',
        postTransferReadback: 'gx-dt-rb',
      },
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [dtCtrl, dtXfer, dtRb] }, { attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY })
  assert.equal(forgedDtRes.confirmed, false, 'forged observedOwnerTenantId must fail closed')
  assert.match(forgedDtRes.reason, /transfer_not_persisted_to_dest_tenant/)
})

test('C-4: economic_conservation NEVER bypasses stub-rejection or own-tenant strict gates', () => {
  const base = signedEntry('gx-e-base', makeStep({
    id: 'gx-e-base', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/api/wallet/w-2', json: { walletId: 'w-2', paidAmount: 100, refundedTotal: 0 },
  }), { timestampMs: 1000 })
  const actStub = signedEntry('gx-e-stub', makeStep({
    id: 'gx-e-stub', arm: 'probe', method: 'POST', status: 202,
    pathAndQuery: '/api/wallet/w-2/refund', json: { jobId: 'job-ref-1', status: 'queued' },
  }), { timestampMs: 1100 })
  const actOwnTenant = signedEntry('gx-e-own', makeStep({
    id: 'gx-e-own', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/wallet/w-2/refund', json: { tenantId: 'org-alpha', refunded: 160 },
  }), { timestampMs: 1150 })
  const finalValid = signedEntry('gx-e-final', makeStep({
    id: 'gx-e-final', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/api/wallet/w-2', json: { walletId: 'w-2', paidAmount: 100, refundedTotal: 160 },
  }), { timestampMs: 1300 })

  // (a) Terminal exchange is a job stub AND postChainReadbackExchangeIds is empty -> MUST reject!
  const stubTermRes = verifyCompositeReceipt({
    chainId: 't2-c4-econ-stub-term',
    terminalVulnClass: 'economic_conservation',
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/wallet/w-2/refund' },
      exchangeIds: ['gx-e-stub'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Refund job queued', producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      summary: 'Claimed over-refund with intermediate job stub as terminal exchange.',
      terminalExchangeId: 'gx-e-stub',
      preChainControlExchangeIds: ['gx-e-base'],
      postChainReadbackExchangeIds: [],
      oracleFamily: 'economic_conservation',
      oracleInput: {
        equation: 'over_refund',
        baselineReadback: 'gx-e-base',
        actions: ['gx-e-stub'],
        finalReadback: 'gx-e-final',
      },
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [base, actStub, finalValid] }, { attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY })
  assert.equal(stubTermRes.confirmed, false, 'economic_conservation with stub terminal exchange and no postChainReadback must fail closed')
  assert.equal(stubTermRes.rejectedBy, 'terminal_impact_unproven')

  // (b) Terminal exchange has own-tenant-only marker AND no postChainReadback AND no denied control -> MUST reject!
  const ownTenantRes = verifyCompositeReceipt({
    chainId: 't2-c4-econ-own-tenant',
    terminalVulnClass: 'economic_conservation',
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/wallet/w-2/refund' },
      exchangeIds: ['gx-e-own'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Own-tenant refund response without readback', producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      summary: 'Claimed economic violation with own-tenant-only terminal response and no readback.',
      terminalExchangeId: 'gx-e-own',
      preChainControlExchangeIds: ['gx-e-base'],
      postChainReadbackExchangeIds: [],
      oracleFamily: 'economic_conservation',
      oracleInput: {
        equation: 'over_refund',
        baselineReadback: 'gx-e-base',
        actions: ['gx-e-own'],
        finalReadback: 'gx-e-final',
      },
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [base, actOwnTenant, finalValid] }, { attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY })
  assert.equal(ownTenantRes.confirmed, false, 'economic_conservation with own-tenant-only terminal response and no post-mutation readback must fail closed')
  assert.equal(ownTenantRes.rejectedBy, 'terminal_impact_unproven')
})

// ============================================================================
// H-11: I6 attacker provenance enforcement
// ============================================================================

test('H-11: I6 rejects pre-seeded admin/owner personas when attackerPersonas omitted and blocks control-arm capability smuggling', () => {
  const cap = 'cap:hop_1:smuggled_admin_cap'
  const ctrl = signedEntry('gx-p-ctrl', makeStep({
    id: 'gx-p-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/admin/vault', json: { error: 'forbidden' },
  }), { timestampMs: 800, actorPersona: 'member_alpha' })
  const adminProbe = signedEntry('gx-p-admin', makeStep({
    id: 'gx-p-admin', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/admin/vault',
    actor: { handle: 'admin_beta', role: 'admin', tenant: 'org-beta', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org-beta', vaultSecret: 'top-secret-42' },
  }), { timestampMs: 1100, actorPersona: 'admin_beta', actorRoleLabel: 'admin (org-beta)' })

  // (a) Admin persona when attackerPersonas is OMITTED -> MUST fail at attacker_provenance!
  const adminOmittedRes = verifyCompositeReceipt({
    chainId: 't2-h11-admin-omitted',
    terminalVulnClass: 'authz_bypass',
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/admin/vault' },
      exchangeIds: ['gx-p-admin'], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Admin shortcut read vault', producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      summary: 'Attempted admin shortcut without attackerPersonas option.',
      terminalExchangeId: 'gx-p-admin',
      preChainControlExchangeIds: ['gx-p-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrl, adminProbe] }, { signingKey: SIGNING_KEY })
  assert.equal(adminOmittedRes.confirmed, false)
  assert.equal(adminOmittedRes.failedStage, 'attacker_provenance')

  // (b) Control-arm exchange executed by owner_beta emitting a capability MUST NOT feed dagCaps!
  const memberProbe1 = signedEntry('gx-p-m1', makeStep({
    id: 'gx-p-m1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/public/ping', json: { pong: true },
  }), { timestampMs: 900, actorPersona: 'member_alpha' })
  const ownerCtrlEmit = signedEntry('gx-p-owner-ctrl', makeStep({
    id: 'gx-p-owner-ctrl', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/owner/token',
    actor: { handle: 'owner_beta', role: 'owner', tenant: 'org-beta', auth: 'bearer', sameSite: null },
    json: { token: 'owner-raw-secret' },
  }), { timestampMs: 950, actorPersona: 'owner_beta', emittedCapabilities: [cap] })
  const hop2Consume = signedEntry('gx-p-h2', makeStep({
    id: 'gx-p-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/admin/vault',
    json: { tenantId: 'org-beta', vaultSecret: 'top-secret-42' },
  }), { timestampMs: 1200, actorPersona: null, consumedCapabilities: [cap] })

  const smuggleRes = verifyCompositeReceipt({
    chainId: 't2-h11-ctrl-cap-smuggle',
    terminalVulnClass: 'authz_bypass',
    hops: [
      {
        hopId: 'hop_1', surface: 'http',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/public/ping' },
        exchangeIds: ['gx-p-m1', 'gx-p-owner-ctrl'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Smuggled capability from owner control exchange', producedCapabilities: [cap], consumedCapabilities: [],
      },
      {
        hopId: 'hop_2', surface: 'http',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/admin/vault' },
        exchangeIds: ['gx-p-h2'], oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Used smuggled owner capability on hop 2', producedCapabilities: [], consumedCapabilities: [cap],
      },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Attempted to smuggle owner capability out of control arm into probe DAG.',
      terminalExchangeId: 'gx-p-h2',
      preChainControlExchangeIds: ['gx-p-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrl, memberProbe1, ownerCtrlEmit, hop2Consume] }, {
    attackerPersonas: ['member_alpha'],
    forbiddenShortcutPersonas: ['owner_beta', 'admin_beta'],
    signingKey: SIGNING_KEY,
  })
  assert.equal(smuggleRes.confirmed, false, 'control-arm capability smuggling must fail closed')
  assert.equal(smuggleRes.failedStage, 'attacker_provenance')
})

// ============================================================================
// H-12: I7 fail-closed without oracleFamily on bare 2xx & 404 entity check
// ============================================================================

test('H-12: composite receipt without oracleFamily CANNOT confirm on a bare 2xx or a 404 for a nonexistent entity', () => {
  const bare200 = signedEntry('gx-bare-200', makeStep({
    id: 'gx-bare-200', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/orders/order-own-1',
    json: { id: 'order-own-1', items: [{ sku: 'book-1', qty: 1 }], total: 25 },
  }), { timestampMs: 1100, entityId: 'order-own-1' })
  const empty204 = signedEntry('gx-empty-204', makeStep({
    id: 'gx-empty-204', arm: 'probe', method: 'POST', status: 204,
    pathAndQuery: '/api/orders/order-own-1/ping',
  }), { timestampMs: 1150, entityId: 'order-own-1' })
  const wrong404 = signedEntry('gx-wrong-404', makeStep({
    id: 'gx-wrong-404', arm: 'control', method: 'GET', status: 404,
    pathAndQuery: '/api/orders/does-not-exist-9999',
    json: { error: 'not_found' },
  }), { timestampMs: 900, entityId: 'does-not-exist-9999' })
  const exact404 = signedEntry('gx-exact-404', makeStep({
    id: 'gx-exact-404', arm: 'control', method: 'GET', status: 404,
    pathAndQuery: '/api/orders/order-own-1',
    json: { error: 'not_found' },
  }), { timestampMs: 900, entityId: 'order-own-1' })

  const transcript: HostSignedTranscript = { entries: [bare200, empty204, wrong404, exact404] }
  const makeBareReceipt = (vulnClass: string, exId: string, preCtrl: string[] = []): CompositeProofReceipt => ({
    chainId: `t2-h12-${vulnClass}-${exId}`,
    terminalVulnClass: vulnClass,
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/orders/order-own-1' },
      exchangeIds: [exId], oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Single bare 2xx without oracleFamily or denied control',
      producedCapabilities: [], consumedCapabilities: [], entityId: 'order-own-1',
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      claimedImpact: 'Claimed terminal impact on a bare 2xx response without oracleFamily.',
      summary: 'Claimed terminal impact on a bare 2xx response without oracleFamily.',
      terminalExchangeId: exId,
      preChainControlExchangeIds: preCtrl,
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  })

  // (a) Bare 2xx for ssrf, business_logic, custom_vuln, privilege_escalation -> ALL MUST FAIL CLOSED
  for (const cls of ['ssrf', 'business_logic', 'custom_vuln', 'privilege_escalation']) {
    const rBody = verifyCompositeReceipt(makeBareReceipt(cls, 'gx-bare-200'), transcript, {
      attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY,
    })
    assert.equal(rBody.confirmed, false, `${cls} must not confirm on bare 200 without control/oracle`)
    assert.equal(rBody.failedStage, 'terminal_impact')

    const rEmpty = verifyCompositeReceipt(makeBareReceipt(cls, 'gx-empty-204'), transcript, {
      attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY,
    })
    assert.equal(rEmpty.confirmed, false, `${cls} must not confirm on bare empty 204 without control/oracle`)
    assert.equal(rEmpty.failedStage, 'terminal_impact')
  }

  // (b) 404 on a DIFFERENT/nonexistent entity ID MUST NOT count as denied control!
  const rWrong404 = verifyCompositeReceipt(makeBareReceipt('bola', 'gx-bare-200', ['gx-wrong-404']), transcript, {
    attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY,
  })
  assert.equal(rWrong404.confirmed, false, '404 for nonexistent entity ID must not satisfy denied control')
  assert.equal(rWrong404.failedStage, 'terminal_impact')

  // (c) 404 on the EXACT SAME entity ID DOES satisfy denied control
  const rExact404 = verifyCompositeReceipt(makeBareReceipt('bola', 'gx-bare-200', ['gx-exact-404']), transcript, {
    attackerPersonas: ['member_alpha'], signingKey: SIGNING_KEY,
  })
  assert.equal(rExact404.confirmed, true, `404 on exact same entity should confirm: ${rExact404.reason}`)
})

// ============================================================================
// H-32: verify-claims.ts ReDoS protection (< 5ms rejection & haystack cap)
// ============================================================================

test('H-32: verify-claims.ts rejects catastrophic backtracking ReDoS regexes in < 5ms and caps haystack', () => {
  const store = new TranscriptStore()
  const evilHaystack = 'a'.repeat(40) + '!'
  const hugeHaystack = 'x'.repeat(10_000) + 'NEEDLE_BEYOND_CAP'
  const rec = store.record({
    op: 'http',
    startedAt: 1000,
    durationMs: 5,
    request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/test', headers: {}, bodyBytes: 0, bodySha256: sha256Hex(''), nonce: 'n1' },
    response: {
      status: 200,
      headers: { 'x-evil': evilHaystack, 'x-huge': hugeHaystack, 'x-auth-mode': 'Bearer tok_abc.123-xyz' },
      bodyBytes: 128,
      bodySha256: sha256Hex(JSON.stringify({ evil: evilHaystack, huge: hugeHaystack, status: 'ready' })),
      mediaType: 'application/json',
    },
    body: JSON.stringify({ evil: evilHaystack, huge: hugeHaystack, status: 'ready' }),
  })

  const redosPatterns = [
    '(a+)+$',
    '((a+)+)+$',
    '(a|aa)+$',
    '(a|a)+$',
    '([a-zA-Z]+)*$',
    'a++',
    '.*.*b',
    '(a)\\1+',
    '(?<=a)b',
    'a'.repeat(257),
    Array.from({ length: 18 }, (_, i) => `k${i}`).join('|'),
    'a{200}',
  ]

  const maxReDoSRejectMs = process.env.CI ? 50 : 5
  for (const pattern of redosPatterns) {
    const t0 = performance.now()
    const headerRes = evaluateClaim(store, { kind: 'header', exchangeId: rec.exchangeId, name: 'x-evil', matches: pattern }, {})
    const jsonRes = evaluateClaim(store, { kind: 'jsonpath', exchangeId: rec.exchangeId, path: '$.evil', matches: pattern }, {})
    const elapsedMs = performance.now() - t0
    assert.equal(headerRes.passed, false, `header claim must reject ReDoS pattern: ${pattern.slice(0, 32)}`)
    assert.equal(jsonRes.passed, false, `jsonpath claim must reject ReDoS pattern: ${pattern.slice(0, 32)}`)
    assert.ok(elapsedMs < maxReDoSRejectMs, `ReDoS pattern "${pattern.slice(0, 32)}" took ${elapsedMs.toFixed(2)}ms (expected < ${maxReDoSRejectMs}ms)`)
  }

  // Haystack length cap (4096 bytes): match beyond 4096 bytes is bounded and does not scan unboundedly
  const hugeHeaderRes = evaluateClaim(store, { kind: 'header', exchangeId: rec.exchangeId, name: 'x-huge', matches: 'NEEDLE_BEYOND_CAP' }, {})
  assert.equal(hugeHeaderRes.passed, false, 'header regex haystack must be capped at 4096 chars')
  const hugeJsonRes = evaluateClaim(store, { kind: 'jsonpath', exchangeId: rec.exchangeId, path: '$.huge', matches: 'NEEDLE_BEYOND_CAP' }, {})
  assert.equal(hugeJsonRes.passed, false, 'jsonpath regex haystack must be capped at 4096 chars')

  // Benign legitimate claim regexes still compile and match cleanly
  assert.equal(compileSafeClaimRegex('^Bearer\\s+[A-Za-z0-9._-]+$').ok, true)
  const okHeader = evaluateClaim(store, { kind: 'header', exchangeId: rec.exchangeId, name: 'x-auth-mode', matches: '^Bearer\\s+[A-Za-z0-9._-]+$' }, {})
  assert.equal(okHeader.passed, true, okHeader.detail)
  const okJson = evaluateClaim(store, { kind: 'jsonpath', exchangeId: rec.exchangeId, path: '$.status', matches: '^(?:ok|ready|settled)$' }, {})
  assert.equal(okJson.passed, true, okJson.detail)
})

// ============================================================================
// LOC discipline ceiling check
// ============================================================================

test('LOC discipline: src/server/composite-receipt.ts <= 750 LOC', () => {
  const lines = readFileSync('src/server/composite-receipt.ts', 'utf8').trimEnd().split('\n').length
  assert.ok(lines <= 750, `composite-receipt.ts LOC ${lines} exceeded ceiling 750`)
})
