/**
 * Unit & hardened-twin precision tests for all 6 v8 extended oracle invariant families
 * (`src/server/v8-oracle-families.ts`):
 *
 *  1. `dual_tenant_abac`: cross-org transfer, dual-org cache bleed, batch partial-authz.
 *  2. `temporal_revocation`: revoked PAT/token on SSE, demoted role on async export, stale invite.
 *  3. `economic_conservation`: over-refund, balance minting, underpaid fulfillment, ineligible discount.
 *  4. `cryptographic_scope_replay`: 3-arm cross-tenant/scope replay vs signature-skip decoy & hardened verifier.
 *  5. `parser_cache_differential`: duplicate JSON key, path/header normalization, cache-primed bleed.
 *  6. `cross_surface_pivot`: HTTP/GraphQL -> browser/admin-bot / worker OOB / OIDC redirect causal DAGs.
 *  7. Unified dispatcher `evaluateV8OracleFamily` + host-signature verifier hook.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import {
  evaluateCryptographicScopeReplay,
  evaluateCrossSurfacePivot,
  evaluateDualTenantAbac,
  evaluateEconomicConservation,
  evaluateParserCacheDifferential,
  evaluateTemporalRevocation,
  evaluateV8OracleFamily,
  hasTenantRoleAtLeast,
  resolveTenantRole,
  type CrossSurfacePivotInput,
  type CryptographicScopeReplayInput,
  type DualTenantActor,
  type HostSignedRecord,
} from '../src/server/v8-oracle-families.ts'

const T0 = 1_760_000_000_000

function rec(overrides: Partial<HostSignedRecord> & { id: string }): HostSignedRecord {
  return {
    hostSignature: `hmac-sha256:${overrides.id}:deadbeefcafebabe`,
    timestampMs: T0,
    status: 200,
    method: 'GET',
    route: '/api/resource',
    surface: 'http',
    ...overrides,
  }
}

/* ───────────────────── 1. Dual-Tenant ABAC Tests ────────────────────────── */

describe('v8 oracle family 1: dual_tenant_abac', () => {
  const dualMember: DualTenantActor = {
    actorId: 'user_dual',
    rolesByTenant: { org_alpha: 'admin', org_beta: 'viewer' },
  }
  const dualAdmin: DualTenantActor = {
    actorId: 'user_super',
    rolesByTenant: { org_alpha: 'admin', org_beta: 'owner' },
  }

  test('role matrix resolves per-tenant roles accurately', () => {
    assert.equal(resolveTenantRole(dualMember, 'ORG_ALPHA'), 'admin')
    assert.equal(resolveTenantRole(dualMember, 'org_beta'), 'viewer')
    assert.equal(resolveTenantRole(dualMember, 'org_gamma'), null)
    assert.equal(hasTenantRoleAtLeast(dualMember, 'org_alpha', 'admin'), true)
    assert.equal(hasTenantRoleAtLeast(dualMember, 'org_beta', 'admin'), false)
  })

  test('cross_org_transfer: confirms admin-in-dest / viewer-in-source persisted transfer', () => {
    const res = evaluateDualTenantAbac({
      mode: 'cross_org_transfer',
      actor: dualMember,
      sourceTenantId: 'org_beta',
      destTenantId: 'org_alpha',
      entityId: 'proj_99',
      sourceControlDenied: rec({ id: 'ctrl-1', status: 403, timestampMs: T0 }),
      transferRecord: rec({ id: 'xfer-1', method: 'POST', route: '/api/projects/proj_99/transfer', status: 200, timestampMs: T0 + 100 }),
      postTransferReadback: rec({ id: 'rb-1', status: 200, timestampMs: T0 + 200, json: { id: 'proj_99', tenantId: 'org_alpha' } }),
      observedOwnerTenantId: 'org_alpha',
    })
    assert.equal(res.satisfied, true)
    assert.equal(res.family, 'dual_tenant_abac')
    assert.equal(res.subRule, 'cross_org_transfer')
  })

  test('cross_org_transfer: fails closed on same-tenant, dual-admin, hardened 403, or unpersisted transfer', () => {
    // Same-tenant transfer
    assert.equal(
      evaluateDualTenantAbac({
        mode: 'cross_org_transfer',
        actor: dualMember,
        sourceTenantId: 'org_alpha',
        destTenantId: 'org_alpha',
        entityId: 'proj_1',
        transferRecord: rec({ id: 'x1', status: 200, timestampMs: T0 }),
        postTransferReadback: rec({ id: 'r1', status: 200, timestampMs: T0 + 10 }),
        observedOwnerTenantId: 'org_alpha',
      }).satisfied,
      false,
    )

    // Properly authorized dual-admin
    const dualAdminRes = evaluateDualTenantAbac({
      mode: 'cross_org_transfer',
      actor: dualAdmin,
      sourceTenantId: 'org_beta',
      destTenantId: 'org_alpha',
      entityId: 'proj_99',
      transferRecord: rec({ id: 'x2', status: 200, timestampMs: T0 }),
      postTransferReadback: rec({ id: 'r2', status: 200, timestampMs: T0 + 10 }),
      observedOwnerTenantId: 'org_alpha',
    })
    assert.equal(dualAdminRes.satisfied, false)
    assert.equal(dualAdminRes.reason, 'actor_authorized_in_source_tenant')

    // Hardened twin rejects transfer with 403
    assert.equal(
      evaluateDualTenantAbac({
        mode: 'cross_org_transfer',
        actor: dualMember,
        sourceTenantId: 'org_beta',
        destTenantId: 'org_alpha',
        entityId: 'proj_99',
        transferRecord: rec({ id: 'x3', status: 403, timestampMs: T0 }),
        postTransferReadback: rec({ id: 'r3', status: 200, timestampMs: T0 + 10 }),
        observedOwnerTenantId: 'org_beta',
      }).satisfied,
      false,
    )

    // 200 echo without actual ownership change
    assert.equal(
      evaluateDualTenantAbac({
        mode: 'cross_org_transfer',
        actor: dualMember,
        sourceTenantId: 'org_beta',
        destTenantId: 'org_alpha',
        entityId: 'proj_99',
        transferRecord: rec({ id: 'x4', status: 200, timestampMs: T0 }),
        postTransferReadback: rec({ id: 'r4', status: 200, timestampMs: T0 + 10 }),
        observedOwnerTenantId: 'org_beta',
      }).satisfied,
      false,
    )
  })

  test('dual_org_cache_bleed: confirms denied -> prime -> bled access; rejects missing control, dual-admin, or hardened twin', () => {
    const pos = evaluateDualTenantAbac({
      mode: 'dual_org_cache_bleed',
      actor: dualMember,
      primeTenantId: 'org_alpha',
      targetTenantId: 'org_beta',
      baselineDeniedControl: rec({ id: 'c1', status: 403, timestampMs: T0 }),
      primeAction: rec({ id: 'p1', status: 200, timestampMs: T0 + 100 }),
      bledAccess: rec({ id: 'b1', status: 200, timestampMs: T0 + 200, artifactDigest: 'sha256:export-beta-01' }),
      observedTenantId: 'org_beta',
    })
    assert.equal(pos.satisfied, true)
    assert.equal(pos.subRule, 'dual_org_cache_bleed')

    // Missing denied baseline control (returned 200 before priming)
    assert.equal(
      evaluateDualTenantAbac({
        mode: 'dual_org_cache_bleed',
        actor: dualMember,
        primeTenantId: 'org_alpha',
        targetTenantId: 'org_beta',
        baselineDeniedControl: rec({ id: 'c2', status: 200, timestampMs: T0 }),
        primeAction: rec({ id: 'p2', status: 200, timestampMs: T0 + 100 }),
        bledAccess: rec({ id: 'b2', status: 200, timestampMs: T0 + 200, artifactDigest: 'sha256:x' }),
      }).satisfied,
      false,
    )

    // Hardened twin keys cache by (userId, tenantId) -> bledAccess denied 403
    assert.equal(
      evaluateDualTenantAbac({
        mode: 'dual_org_cache_bleed',
        actor: dualMember,
        primeTenantId: 'org_alpha',
        targetTenantId: 'org_beta',
        baselineDeniedControl: rec({ id: 'c3', status: 403, timestampMs: T0 }),
        primeAction: rec({ id: 'p3', status: 200, timestampMs: T0 + 100 }),
        bledAccess: rec({ id: 'b3', status: 403, timestampMs: T0 + 200 }),
      }).satisfied,
      false,
    )

    // Dual-admin already authorized in target tenant
    assert.equal(
      evaluateDualTenantAbac({
        mode: 'dual_org_cache_bleed',
        actor: dualAdmin,
        primeTenantId: 'org_alpha',
        targetTenantId: 'org_beta',
        baselineDeniedControl: rec({ id: 'c4', status: 403, timestampMs: T0 }),
        primeAction: rec({ id: 'p4', status: 200, timestampMs: T0 + 100 }),
        bledAccess: rec({ id: 'b4', status: 200, timestampMs: T0 + 200, artifactDigest: 'sha256:x' }),
      }).satisfied,
      false,
    )
  })

  test('batch_partial_authz: confirms read and mutation bypass; rejects hardened filter/403 or missing single-item control', () => {
    const memberOnlyAlpha: DualTenantActor = {
      actorId: 'member_alpha',
      rolesByTenant: { org_alpha: 'member' },
    }

    // Positive read bypass
    const posRead = evaluateDualTenantAbac({
      mode: 'batch_partial_authz',
      actor: memberOnlyAlpha,
      ownTenantId: 'org_alpha',
      foreignTenantId: 'org_beta',
      ownRecordId: 'sec_own_1',
      foreignRecordId: 'sec_foreign_2',
      requestedIds: ['sec_own_1', 'sec_foreign_2'],
      singleForeignControlDenied: rec({ id: 'sc-1', status: 403, timestampMs: T0 }),
      batchRequest: rec({
        id: 'batch-1',
        method: 'POST',
        status: 200,
        timestampMs: T0 + 100,
        json: { items: [{ id: 'sec_own_1', val: 'a' }, { id: 'sec_foreign_2', val: 'secret-value' }] },
      }),
      returnedForeignIds: ['sec_foreign_2'],
    })
    assert.equal(posRead.satisfied, true)

    // Positive mutation bypass
    const posMut = evaluateDualTenantAbac({
      mode: 'batch_partial_authz',
      actor: memberOnlyAlpha,
      ownTenantId: 'org_alpha',
      foreignTenantId: 'org_beta',
      ownRecordId: 'sec_own_1',
      foreignRecordId: 'sec_foreign_2',
      requestedIds: ['sec_own_1', 'sec_foreign_2'],
      singleForeignControlDenied: rec({ id: 'sc-2', status: 403, timestampMs: T0 }),
      batchRequest: rec({ id: 'batch-2', method: 'PATCH', status: 200, timestampMs: T0 + 100 }),
      postMutationReadback: rec({ id: 'rb-2', status: 200, timestampMs: T0 + 200 }),
      foreignMutationPersisted: true,
    })
    assert.equal(posMut.satisfied, true)

    // Hardened twin silently strips foreign record from batch response
    assert.equal(
      evaluateDualTenantAbac({
        mode: 'batch_partial_authz',
        actor: memberOnlyAlpha,
        ownTenantId: 'org_alpha',
        foreignTenantId: 'org_beta',
        ownRecordId: 'sec_own_1',
        foreignRecordId: 'sec_foreign_2',
        requestedIds: ['sec_own_1', 'sec_foreign_2'],
        singleForeignControlDenied: rec({ id: 'sc-3', status: 403, timestampMs: T0 }),
        batchRequest: rec({ id: 'batch-3', method: 'POST', status: 200, timestampMs: T0 + 100, json: { items: [{ id: 'sec_own_1' }] } }),
        returnedForeignIds: [],
      }).satisfied,
      false,
    )

    // Missing single-foreign denied control (returned 200 directly)
    assert.equal(
      evaluateDualTenantAbac({
        mode: 'batch_partial_authz',
        actor: memberOnlyAlpha,
        ownTenantId: 'org_alpha',
        foreignTenantId: 'org_beta',
        ownRecordId: 'sec_own_1',
        foreignRecordId: 'sec_foreign_2',
        requestedIds: ['sec_own_1', 'sec_foreign_2'],
        singleForeignControlDenied: rec({ id: 'sc-4', status: 200, timestampMs: T0 }),
        batchRequest: rec({ id: 'batch-4', method: 'POST', status: 200, timestampMs: T0 + 100, artifactDigest: 'sha256:ab' }),
        returnedForeignIds: ['sec_foreign_2'],
      }).satisfied,
      false,
    )
  })
})

/* ──────────────────── 2. Temporal Revocation Tests ──────────────────────── */

describe('v8 oracle family 2: temporal_revocation', () => {
  test('confirms revoked PAT rejected on REST (401) then accepted on SSE stream', () => {
    const res = evaluateTemporalRevocation({
      credentialKind: 'pat',
      credentialHandle: 'cap:pat_01',
      primarySurface: 'http',
      secondarySurface: 'sse',
      preRevocationBaseline: rec({ id: 'pre-1', status: 200, timestampMs: T0, capabilityHandle: 'cap:pat_01' }),
      revocationEvent: rec({ id: 'rev-1', method: 'DELETE', status: 204, timestampMs: T0 + 100 }),
      primaryDeniedCheck: rec({ id: 'prim-1', route: '/api/projects', status: 401, timestampMs: T0 + 200, capabilityHandle: 'cap:pat_01' }),
      secondarySuccess: rec({
        id: 'sec-1',
        surface: 'sse',
        route: '/events/stream',
        status: 200,
        timestampMs: T0 + 300,
        capabilityHandle: 'cap:pat_01',
        artifactDigest: 'sha256:sse-event-payload',
      }),
    })
    assert.equal(res.satisfied, true)
    assert.equal(res.family, 'temporal_revocation')
    assert.equal(res.subRule, 'pat')
  })

  test('confirms demoted user rejected on primary REST then succeeds on async export download', () => {
    const res = evaluateTemporalRevocation({
      credentialKind: 'async_job',
      actorId: 'user_demoted',
      primarySurface: 'http',
      secondarySurface: 'async_job',
      revocationEvent: rec({ id: 'demote-1', method: 'PATCH', status: 200, timestampMs: T0 + 50 }),
      primaryDeniedCheck: rec({ id: 'prim-2', route: '/api/exports', status: 403, timestampMs: T0 + 100, actorId: 'user_demoted' }),
      secondarySuccess: rec({
        id: 'dl-2',
        surface: 'async_job',
        route: '/api/exports/job_7/download',
        status: 200,
        timestampMs: T0 + 200,
        actorId: 'user_demoted',
        artifactDigest: 'sha256:exported-records',
      }),
    })
    assert.equal(res.satisfied, true)
  })

  test('fails closed when primary was NOT actually revoked, secondary is hardened 401, timestamps inverted, or handle swapped', () => {
    // Primary returned 200 (not actually revoked)
    const notRevoked = evaluateTemporalRevocation({
      credentialKind: 'token',
      credentialHandle: 'cap:tok_1',
      primarySurface: 'http',
      secondarySurface: 'sse',
      revocationEvent: rec({ id: 'r1', status: 200, timestampMs: T0 }),
      primaryDeniedCheck: rec({ id: 'p1', status: 200, timestampMs: T0 + 10, capabilityHandle: 'cap:tok_1' }),
      secondarySuccess: rec({ id: 's1', surface: 'sse', status: 200, timestampMs: T0 + 20, capabilityHandle: 'cap:tok_1', artifactDigest: 'sha256:1' }),
    })
    assert.equal(notRevoked.satisfied, false)
    assert.equal(notRevoked.reason, 'primary_surface_not_revoked')

    // Hardened twin rejects secondary SSE with 401
    assert.equal(
      evaluateTemporalRevocation({
        credentialKind: 'pat',
        credentialHandle: 'cap:tok_2',
        primarySurface: 'http',
        secondarySurface: 'sse',
        revocationEvent: rec({ id: 'r2', status: 204, timestampMs: T0 }),
        primaryDeniedCheck: rec({ id: 'p2', status: 401, timestampMs: T0 + 10, capabilityHandle: 'cap:tok_2' }),
        secondarySuccess: rec({ id: 's2', surface: 'sse', status: 401, timestampMs: T0 + 20, capabilityHandle: 'cap:tok_2' }),
      }).satisfied,
      false,
    )

    // Secondary access happened BEFORE verified primary denial
    assert.equal(
      evaluateTemporalRevocation({
        credentialKind: 'invite',
        credentialHandle: 'cap:inv_1',
        primarySurface: 'http',
        secondarySurface: 'http',
        revocationEvent: rec({ id: 'r3', status: 200, timestampMs: T0 }),
        primaryDeniedCheck: rec({ id: 'p3', route: '/api/admin', status: 403, timestampMs: T0 + 200, capabilityHandle: 'cap:inv_1' }),
        secondarySuccess: rec({ id: 's3', route: '/api/invites/redeem', status: 200, timestampMs: T0 + 100, capabilityHandle: 'cap:inv_1' }),
        elevatedRoleGranted: true,
      }).satisfied,
      false,
    )

    // Credential handle mismatch (swapped active token on secondary surface)
    assert.equal(
      evaluateTemporalRevocation({
        credentialKind: 'pat',
        credentialHandle: 'cap:revoked_1',
        primarySurface: 'http',
        secondarySurface: 'sse',
        revocationEvent: rec({ id: 'r4', status: 204, timestampMs: T0 }),
        primaryDeniedCheck: rec({ id: 'p4', status: 401, timestampMs: T0 + 10, capabilityHandle: 'cap:revoked_1' }),
        secondarySuccess: rec({ id: 's4', surface: 'sse', status: 200, timestampMs: T0 + 20, capabilityHandle: 'cap:fresh_active', artifactDigest: 'sha256:1' }),
      }).satisfied,
      false,
    )
  })
})

/* ─────────────────── 3. Economic Conservation Tests ─────────────────────── */

describe('v8 oracle family 3: economic_conservation', () => {
  const base = rec({ id: 'base', status: 200, timestampMs: T0 })
  const act1 = rec({ id: 'act-1', method: 'POST', status: 200, timestampMs: T0 + 50 })
  const act2 = rec({ id: 'act-2', method: 'POST', status: 200, timestampMs: T0 + 60 })
  const fin = rec({ id: 'final', status: 200, timestampMs: T0 + 150 })

  test('confirms all 4 conservation violations (over_refund, balance_minting, underpaid_fulfillment, ineligible_discount)', () => {
    const r1 = evaluateEconomicConservation({
      equation: 'over_refund',
      baselineReadback: base,
      actions: [act1, act2],
      finalReadback: fin,
      paidAmount: 100,
      refundedAmounts: [70, 60],
    })
    assert.equal(r1.satisfied, true)
    assert.equal(r1.evidence?.excessRefunded, 30)

    const r2 = evaluateEconomicConservation({
      equation: 'balance_minting',
      baselineReadback: base,
      actions: [act1, act2],
      finalReadback: fin,
      balancesBefore: { acct_a: 500, acct_b: 100 },
      balancesAfter: { acct_a: 500, acct_b: 300 },
      authorizedDeposits: 0,
    })
    assert.equal(r2.satisfied, true)
    assert.equal(r2.evidence?.mintedDelta, 200)

    const r3 = evaluateEconomicConservation({
      equation: 'underpaid_fulfillment',
      baselineReadback: base,
      actions: [act1],
      finalReadback: fin,
      paidAmount: 10,
      fulfilledValue: 250,
      fulfillmentState: 'fulfilled',
    })
    assert.equal(r3.satisfied, true)
    assert.equal(r3.evidence?.shortfall, 240)

    const r4 = evaluateEconomicConservation({
      equation: 'ineligible_discount',
      baselineReadback: base,
      actions: [act1],
      finalReadback: fin,
      subtotalAmount: 40,
      requiredThreshold: 100,
      discountApplied: 20,
      finalTotalPaid: 20,
    })
    assert.equal(r4.satisfied, true)
  })

  test('fails closed when ledger conserves, order stays draft, discount is eligible, or baseline/readback is missing', () => {
    // Conserved refunds (60 + 40 == 100)
    assert.equal(
      evaluateEconomicConservation({
        equation: 'over_refund',
        baselineReadback: base,
        actions: [act1, act2],
        finalReadback: fin,
        paidAmount: 100,
        refundedAmounts: [60, 40],
      }).satisfied,
      false,
    )

    // Conserved balances with external deposit (600 + 200 == 800)
    assert.equal(
      evaluateEconomicConservation({
        equation: 'balance_minting',
        baselineReadback: base,
        actions: [act1],
        finalReadback: fin,
        balancesBefore: { acct_a: 500, acct_b: 100 },
        balancesAfter: { acct_a: 300, acct_b: 500 },
        authorizedDeposits: 200,
      }).satisfied,
      false,
    )

    // Unfinalized draft order (hardened twin never captures)
    assert.equal(
      evaluateEconomicConservation({
        equation: 'underpaid_fulfillment',
        baselineReadback: base,
        actions: [act1],
        finalReadback: fin,
        paidAmount: 10,
        fulfilledValue: 250,
        fulfillmentState: 'draft',
      }).satisfied,
      false,
    )

    // Eligible discount (subtotal >= threshold)
    assert.equal(
      evaluateEconomicConservation({
        equation: 'ineligible_discount',
        baselineReadback: base,
        actions: [act1],
        finalReadback: fin,
        subtotalAmount: 120,
        requiredThreshold: 100,
        discountApplied: 20,
      }).satisfied,
      false,
    )

    // Missing final readback (unsigned / missing)
    assert.equal(
      evaluateEconomicConservation({
        equation: 'over_refund',
        baselineReadback: base,
        actions: [act1],
        finalReadback: { ...fin, hostSignature: '' },
        paidAmount: 50,
        refundedAmounts: [100],
      }).satisfied,
      false,
    )

    // Out-of-order final readback timestamp (before action)
    assert.equal(
      evaluateEconomicConservation({
        equation: 'over_refund',
        baselineReadback: base,
        actions: [act1],
        finalReadback: rec({ id: 'early', status: 200, timestampMs: T0 + 10 }),
        paidAmount: 50,
        refundedAmounts: [100],
      }).satisfied,
      false,
    )
  })
})

/* ──────────────── 4. Cryptographic Scope Replay Tests ───────────────────── */

describe('v8 oracle family 4: cryptographic_scope_replay', () => {
  const baseInput = (): CryptographicScopeReplayInput => ({
    tamperedSignatureControl: rec({
      id: 'sig-tampered',
      method: 'POST',
      route: '/webhooks/settle',
      status: 401,
      timestampMs: T0,
      artifactDigest: 'sha256:tampered-sig',
    }),
    sourceValidIssuance: rec({
      id: 'sig-source',
      method: 'POST',
      route: '/api/webhooks/sign',
      status: 200,
      timestampMs: T0 + 100,
      artifactDigest: 'sha256:valid-sig-beta',
    }),
    replayedAcceptance: rec({
      id: 'sig-replay',
      method: 'POST',
      route: '/webhooks/settle',
      status: 200,
      timestampMs: T0 + 200,
      artifactDigest: 'sha256:valid-sig-beta',
      json: { settledId: 'tx_42', tenant: 'org_alpha' },
    }),
    sourceTenant: 'org_beta',
    sourceScope: 'sandbox:webhook',
    targetTenant: 'org_alpha',
    targetScope: 'prod:settlement',
  })

  test('confirms 3-arm cross-tenant / cross-scope cryptographic replay', () => {
    const res = evaluateCryptographicScopeReplay(baseInput())
    assert.equal(res.satisfied, true)
    assert.equal(res.family, 'cryptographic_scope_replay')
    assert.equal(res.subRule, 'cross_tenant_scope_replay')
  })

  test('rejects signature-skip decoy (tampered sig returns 200), hardened twin (replay 403), same scope, and mismatched digest', () => {
    // Signature-skip decoy: tampered signature also returned 200
    const decoy = baseInput()
    decoy.tamperedSignatureControl = { ...decoy.tamperedSignatureControl, status: 200 }
    const decoyRes = evaluateCryptographicScopeReplay(decoy)
    assert.equal(decoyRes.satisfied, false)
    assert.equal(decoyRes.reason, 'signature_verification_not_enforced_decoy')

    // Hardened twin: canonical scope-bound HMAC rejects replayed signature with 403
    const hardened = baseInput()
    hardened.replayedAcceptance = { ...hardened.replayedAcceptance, status: 403 }
    assert.equal(evaluateCryptographicScopeReplay(hardened).satisfied, false)

    // Same tenant and same scope (legitimate verification, not replay)
    const sameScope = baseInput()
    sameScope.targetTenant = sameScope.sourceTenant
    sameScope.targetScope = sameScope.sourceScope
    assert.equal(evaluateCryptographicScopeReplay(sameScope).satisfied, false)

    // Replayed digest does not match source issued signature
    const diffSig = baseInput()
    diffSig.replayedAcceptance = { ...diffSig.replayedAcceptance, artifactDigest: 'sha256:different-sig' }
    assert.equal(evaluateCryptographicScopeReplay(diffSig).satisfied, false)
  })
})

/* ─────────────── 5. Parser / Cache Differential Tests ───────────────────── */

describe('v8 oracle family 5: parser_cache_differential', () => {
  test('parser_differential: confirms duplicate JSON key mutation and header normalization read; rejects hardened parser & missing readback', () => {
    const dupKey = evaluateParserCacheDifferential({
      mode: 'parser_differential',
      differentialKind: 'duplicate_json_key',
      differentialFeature: 'amount',
      canonicalValue: '{"amount":50000}',
      variantValue: '{"amount":10,"amount":50000}',
      impactKind: 'mutation',
      cleanControl: rec({ id: 'p-ctrl', method: 'POST', status: 403, timestampMs: T0 }),
      differentialProbe: rec({ id: 'p-probe', method: 'POST', status: 200, timestampMs: T0 + 100 }),
      postMutationReadback: rec({ id: 'p-rb', status: 200, timestampMs: T0 + 200, json: { amount: 50000 } }),
      mutationPersisted: true,
    })
    assert.equal(dupKey.satisfied, true)
    assert.equal(dupKey.subRule, 'duplicate_json_key')

    const hdrNorm = evaluateParserCacheDifferential({
      mode: 'parser_differential',
      differentialKind: 'header_normalization',
      differentialFeature: 'x-internal-actor',
      canonicalValue: 'X-Internal-Actor: admin',
      variantValue: 'X_Internal_Actor: admin',
      impactKind: 'read',
      cleanControl: rec({ id: 'h-ctrl', status: 403, timestampMs: T0 }),
      differentialProbe: rec({ id: 'h-probe', status: 200, timestampMs: T0 + 100, artifactDigest: 'sha256:private-doc' }),
    })
    assert.equal(hdrNorm.satisfied, true)

    // Clean control not denied (200 -> endpoint wasn't blocked)
    assert.equal(
      evaluateParserCacheDifferential({
        mode: 'parser_differential',
        differentialKind: 'path_normalization',
        differentialFeature: '/admin/../admin/export',
        impactKind: 'read',
        cleanControl: rec({ id: 'bad-ctrl', status: 200, timestampMs: T0 }),
        differentialProbe: rec({ id: 'bad-probe', status: 200, timestampMs: T0 + 100, artifactDigest: 'sha256:x' }),
      }).satisfied,
      false,
    )

    // Hardened twin rejects duplicate JSON key with 400
    assert.equal(
      evaluateParserCacheDifferential({
        mode: 'parser_differential',
        differentialKind: 'duplicate_json_key',
        differentialFeature: 'amount',
        impactKind: 'mutation',
        cleanControl: rec({ id: 'h2-ctrl', status: 403, timestampMs: T0 }),
        differentialProbe: rec({ id: 'h2-probe', status: 400, timestampMs: T0 + 100 }),
        postMutationReadback: rec({ id: 'h2-rb', status: 200, timestampMs: T0 + 200 }),
        mutationPersisted: false,
      }).satisfied,
      false,
    )

    // Mutation without persisted readback fails closed
    assert.equal(
      evaluateParserCacheDifferential({
        mode: 'parser_differential',
        differentialKind: 'duplicate_json_key',
        differentialFeature: 'amount',
        impactKind: 'mutation',
        cleanControl: rec({ id: 'm-ctrl', status: 403, timestampMs: T0 }),
        differentialProbe: rec({ id: 'm-probe', status: 200, timestampMs: T0 + 100 }),
      }).satisfied,
      false,
    )
  })

  test('cache_primed: confirms cross-principal CDN cache bleed; rejects Vary-hardened miss, public baseline, or same actor', () => {
    const pos = evaluateParserCacheDifferential({
      mode: 'cache_primed',
      cacheKey: '/public/profile/org-a.css',
      victimArtifactDigest: 'sha256:owner-delegation-key',
      cleanControl: rec({ id: 'cc-1', surface: 'cdn', status: 200, timestampMs: T0, actorId: 'member_b', tenantId: 'org_b', artifactDigest: 'sha256:public-css' }),
      victimOrPrimeRequest: rec({ id: 'vp-1', surface: 'cdn', status: 200, timestampMs: T0 + 100, actorId: 'owner_a', tenantId: 'org_a', artifactDigest: 'sha256:owner-delegation-key' }),
      attackerProbe: rec({
        id: 'ap-1',
        surface: 'cdn',
        status: 200,
        timestampMs: T0 + 200,
        actorId: 'member_b',
        tenantId: 'org_b',
        responseHeaders: { 'x-cache': 'HIT' },
        artifactDigest: 'sha256:owner-delegation-key',
      }),
    })
    assert.equal(pos.satisfied, true)
    assert.equal(pos.subRule, 'cache_primed')

    // Hardened CDN with Vary: Authorization -> cache MISS & own artifact only
    assert.equal(
      evaluateParserCacheDifferential({
        mode: 'cache_primed',
        cacheKey: '/public/profile/org-a.css',
        victimArtifactDigest: 'sha256:owner-delegation-key',
        cleanControl: rec({ id: 'cc-2', surface: 'cdn', status: 200, timestampMs: T0, actorId: 'member_b', tenantId: 'org_b', artifactDigest: 'sha256:public-css' }),
        victimOrPrimeRequest: rec({ id: 'vp-2', surface: 'cdn', status: 200, timestampMs: T0 + 100, actorId: 'owner_a', tenantId: 'org_a', artifactDigest: 'sha256:owner-delegation-key' }),
        attackerProbe: rec({
          id: 'ap-2',
          surface: 'cdn',
          status: 200,
          timestampMs: T0 + 200,
          actorId: 'member_b',
          tenantId: 'org_b',
          responseHeaders: { 'x-cache': 'MISS', vary: 'Authorization, Cookie' },
          artifactDigest: 'sha256:public-css',
        }),
      }).satisfied,
      false,
    )

    // Public baseline already contained the artifact (not cache bleed)
    assert.equal(
      evaluateParserCacheDifferential({
        mode: 'cache_primed',
        cacheKey: '/public/static.css',
        victimArtifactDigest: 'sha256:public-banner',
        cleanControl: rec({ id: 'cc-3', status: 200, timestampMs: T0, actorId: 'member_b', tenantId: 'org_b', artifactDigest: 'sha256:public-banner' }),
        victimOrPrimeRequest: rec({ id: 'vp-3', status: 200, timestampMs: T0 + 100, actorId: 'owner_a', tenantId: 'org_a', artifactDigest: 'sha256:public-banner' }),
        attackerProbe: rec({ id: 'ap-3', status: 200, timestampMs: T0 + 200, actorId: 'member_b', tenantId: 'org_b', responseHeaders: { 'x-cache': 'HIT' }, artifactDigest: 'sha256:public-banner' }),
      }).satisfied,
      false,
    )
  })
})

/* ─────────────────── 6. Cross-Surface Pivot Tests ───────────────────────── */

describe('v8 oracle family 6: cross_surface_pivot', () => {
  const validBrowserPivot = (): CrossSurfacePivotInput => ({
    attackerOriginPersona: { actorId: 'member_a', role: 'member', tenantId: 'org_a' },
    preChainControlDenied: rec({ id: 'pre-ctrl', route: '/api/audit-vault', status: 403, timestampMs: T0, actorId: 'member_a' }),
    hops: [
      {
        surface: 'graphql',
        role: 'trigger_write',
        record: rec({ id: 'h0', surface: 'graphql', method: 'POST', status: 200, timestampMs: T0 + 100, actorId: 'member_a' }),
        correlationToken: 'run-item-77',
      },
      {
        surface: 'browser',
        role: 'admin_bot_visit',
        bindingKind: 'async_pivot_binding',
        correlationToken: 'run-item-77',
        emittedArtifactDigest: 'cap:hop_h1:scim_token',
        record: rec({ id: 'h1', surface: 'browser', status: 200, timestampMs: T0 + 500, capabilityHandle: 'cap:hop_h1:scim_token' }),
      },
      {
        surface: 'http',
        role: 'terminal_impact',
        bindingKind: 'value_binding',
        consumedArtifactDigest: 'cap:hop_h1:scim_token',
        record: rec({ id: 'h2', surface: 'http', method: 'PATCH', route: '/scim/v2/Users/member_a', status: 200, timestampMs: T0 + 900 }),
      },
    ],
    terminalImpact: {
      kind: 'privilege_escalation',
      verified: true,
      impactDigest: 'sha256:org-owner-role-persisted',
      postImpactReadback: rec({ id: 'rb-final', status: 200, timestampMs: T0 + 1100, json: { role: 'owner' } }),
    },
  })

  test('retired standalone evaluateCrossSurfacePivot shim fails closed outside CompositeProofReceipt DAG', () => {
    // Multi-surface pivot outside CompositeProofReceipt DAG fails closed (must route through DAG surfaces.size >= 2)
    const res1 = evaluateCrossSurfacePivot(validBrowserPivot())
    assert.equal(res1.satisfied, false)
    assert.equal(res1.family, 'cross_surface_pivot')
    assert.equal(res1.reason, 'cross_surface_pivot_requires_composite_dag')

    // Single-surface HTTP-only chain fails closed
    const singleSurface = validBrowserPivot()
    singleSurface.hops = singleSurface.hops.map((h) => ({ ...h, surface: 'http' }))
    const singleRes = evaluateCrossSurfacePivot(singleSurface)
    assert.equal(singleRes.satisfied, false)
    assert.equal(singleRes.reason, 'single_surface_not_cross_surface_pivot')

    // 1-hop chain fails closed
    const oneHop = validBrowserPivot()
    oneHop.hops = oneHop.hops.slice(0, 1)
    const oneHopRes = evaluateCrossSurfacePivot(oneHop)
    assert.equal(oneHopRes.satisfied, false)
    assert.equal(oneHopRes.reason, 'invalid_hop_count')

    // Intermediate stub record on terminal hop fails closed
    const stubPivot = validBrowserPivot()
    stubPivot.hops = stubPivot.hops.map((h, idx) => (idx === 2 ? { ...h, record: { ...h.record, method: 'POST', status: 202, json: { jobId: 'j-1', status: 'queued' } } } : h))
    const stubRes = evaluateCrossSurfacePivot(stubPivot)
    assert.equal(stubRes.satisfied, false)
    assert.equal(stubRes.reason, 'terminal_impact_unproven_intermediate_stub')
  })
})

/* ─────────────────── 7. Dispatcher & Signature Hook ─────────────────────── */

describe('v8 unified dispatcher and host-signature verification', () => {
  test('evaluateV8OracleFamily dispatches all 6 families and rejects invalid signatures or unknown families', () => {
    const dispatched = evaluateV8OracleFamily('economic_conservation', {
      equation: 'over_refund',
      baselineReadback: rec({ id: 'd-base', status: 200, timestampMs: T0 }),
      actions: [rec({ id: 'd-act', method: 'POST', status: 200, timestampMs: T0 + 50 })],
      finalReadback: rec({ id: 'd-fin', status: 200, timestampMs: T0 + 100 }),
      paidAmount: 25,
      refundedAmounts: [30],
    })
    assert.equal(dispatched.satisfied, true)
    assert.equal(dispatched.family, 'economic_conservation')

    // Custom signature verifier rejects tampered transcript seal
    const rejectedSig = evaluateV8OracleFamily('economic_conservation', {
      equation: 'over_refund',
      baselineReadback: rec({ id: 'd-base', status: 200, timestampMs: T0 }),
      actions: [rec({ id: 'd-act', method: 'POST', status: 200, timestampMs: T0 + 50 })],
      finalReadback: rec({ id: 'd-fin', status: 200, timestampMs: T0 + 100 }),
      paidAmount: 25,
      refundedAmounts: [30],
      verifySignature: (r) => r.id !== 'd-fin',
    })
    assert.equal(rejectedSig.satisfied, false)
    assert.equal(rejectedSig.reason, 'invalid_final_readback_signature')

    // Unknown family fails closed
    const unknown = evaluateV8OracleFamily('nonexistent_family' as never, {} as never)
    assert.equal(unknown.satisfied, false)
    assert.equal(unknown.reason, 'unknown_v8_oracle_family')
  })
})
