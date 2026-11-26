// @kernel @fixes R3-12
/**
 * R3-12 fast class-level regression guard for the two confirmation-kernel false positives surfaced
 * by the executable oracle x benign-archetype matrix:
 *   1. FP #1 (`src/server/oracle-invariants.ts`): honest authorized wallet/accumulator deposits
 *      (single or repeated, sibling `/balance` + `/deposit` routes, starting at 100 or 0, with
 *      short-digit substring collision `'25'` in `'125'`) MUST NEVER confirm `business_logic`.
 *   2. FP #2 (`src/server/oracle-invariants.ts` + `src/server/proof-receipt.ts`): same-tenant
 *      org-shared read pairing `owner_a` 200 control + `anon` 401 login-wall control + `owner_b`
 *      403 + `viewer_a` 200 MUST NEVER confirm `bola`/`idor`/`cross_tenant_read`/`bfla`/`disclosure`.
 *   3. TP preservation: genuine business-logic tampers (direct `PATCH { balance: 999 }`,
 *      double-redeem with 409 refusal, double-withdraw crossing floor on sibling `/balance` &
 *      `/withdraw` routes, single-step overdraft crossing floor, declared invariant price tamper,
 *      unauthorized peer mutation) and genuine authorization/BFLA/auth-bypass TPs remain 100% GREEN.
 *
 * Defensive QA framing: zero-network synthetic host-observed exchanges only.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import {
  assessAuthorizationImpact,
  assessBusinessLogicImpact,
  type ActorIdentity,
  type ImpactStep,
} from '../src/server/oracle-invariants.ts'
import {
  buildProofReceipt,
  verifyReceipt,
  type ReceiptTranscript,
  type ReceiptTranscriptEntry,
} from '../src/server/proof-receipt.ts'

const ORIGIN = 'https://benign.example.test'

const ACTORS = {
  anon: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null } satisfies ActorIdentity,
  anonCookie: { handle: null, role: null, tenant: null, auth: 'cookie', sameSite: 'Lax' } satisfies ActorIdentity,
  ownerA: { handle: 'owner_a', role: 'owner', tenant: 'tenant-a', auth: 'bearer', sameSite: null } satisfies ActorIdentity,
  memberA: { handle: 'member_a', role: 'member', tenant: 'tenant-a', auth: 'cookie', sameSite: 'Lax' } satisfies ActorIdentity,
  viewerA: { handle: 'viewer_a', role: 'viewer', tenant: 'tenant-a', auth: 'bearer', sameSite: null } satisfies ActorIdentity,
  ownerB: { handle: 'owner_b', role: 'owner', tenant: 'tenant-b', auth: 'bearer', sameSite: null } satisfies ActorIdentity,
  memberB: { handle: 'member_b', role: 'member', tenant: 'tenant-b', auth: 'bearer', sameSite: null } satisfies ActorIdentity,
}

function makeStep(overrides: Partial<ImpactStep> & { id: string }): ImpactStep {
  const pathAndQuery = overrides.pathAndQuery ?? overrides.route ?? '/'
  const route = overrides.route ?? pathAndQuery.split('?')[0] ?? '/'
  const body = overrides.body ?? (overrides.json !== undefined ? JSON.stringify(overrides.json) : '')
  return {
    arm: 'probe',
    method: 'GET',
    status: 200,
    actor: ACTORS.memberA,
    ...overrides,
    route,
    pathAndQuery,
    body,
  }
}

function makeTranscript(steps: readonly ImpactStep[]): ReceiptTranscript {
  const entries: ReceiptTranscriptEntry[] = steps.map((step, idx) => ({
    exchangeId: step.id,
    origin: ORIGIN,
    timestampMs: 1_700_000_000_000 + idx * 50,
    step: { ...step, seq: step.seq ?? idx + 1 },
  }))
  return { entries }
}

describe('R3-12 FP #1: honest authorized wallet/accumulator deposits never confirm business_logic', () => {
  test('rejects repeated honest wallet deposits across sibling /balance and /deposit routes (assessBusinessLogicImpact + verifyReceipt)', () => {
    const steps: ImpactStep[] = [
      makeStep({ id: 'bl_before', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', status: 200, actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: 100, limit: 1000, tenant_id: 'tenant-a' } }),
      makeStep({ id: 'bl_act1', seq: 2, arm: 'probe', method: 'POST', pathAndQuery: '/api/wallets/acct_a/deposit', status: 200, actor: ACTORS.memberA, requestJson: { amount: 25, qty: 1 }, json: { deposited: 25, balance: 125 } }),
      makeStep({ id: 'bl_mid', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', status: 200, actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: 125, limit: 1000, tenant_id: 'tenant-a' } }),
      makeStep({ id: 'bl_act2', seq: 4, arm: 'probe', method: 'POST', pathAndQuery: '/api/wallets/acct_a/deposit', status: 200, actor: ACTORS.memberA, requestJson: { amount: 25, qty: 1 }, json: { deposited: 25, balance: 150 } }),
      makeStep({ id: 'bl_after', seq: 5, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', status: 200, actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: 150, limit: 1000, tenant_id: 'tenant-a' } }),
    ]

    const direct = assessBusinessLogicImpact({ impactClass: 'business_logic', steps })
    assert.equal(direct.satisfied, false, `repeated honest deposit must reject, got: ${direct.reason}`)
    assert.equal(direct.evidence.repeatedTransition, false)

    const receipt = buildProofReceipt({
      vulnClass: 'business_logic',
      target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/wallets/acct_a/deposit' },
      exchangeIds: steps.map(s => s.id),
      claimedDelta: 'Repeated honest wallet deposit accumulation.',
    })
    const verified = verifyReceipt(receipt, makeTranscript(steps))
    assert.equal(verified.confirmed, false, `verifyReceipt must reject repeated honest deposit, got: ${verified.reason}`)
  })

  test('rejects single honest wallet deposit (starting from 100 OR starting from 0) and arithmetic-delta / seats / credits accumulators', () => {
    // 1. Single deposit 100 -> 125 (substring '25' inside '125' must NOT attribute or confirm)
    for (const startBalance of [0, 100]) {
      const steps: ImpactStep[] = [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: startBalance } }),
        makeStep({ id: 'd1', seq: 2, arm: 'probe', method: 'POST', pathAndQuery: '/api/wallets/acct_a/deposit', actor: ACTORS.memberA, requestJson: { amount: 25 }, json: { deposited: 25, balance: startBalance + 25 } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: startBalance + 25 } }),
      ]
      const res = assessBusinessLogicImpact({ impactClass: 'business_logic', steps })
      assert.equal(res.satisfied, false, `single honest deposit (start=${startBalance}) must reject, got: ${res.reason}`)
    }

    // 2. Even if an accumulator POST echoes a field name matching `balance` on `/deposit`
    const depositBalanceKey = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: 0 } }),
        makeStep({ id: 'd1', seq: 2, arm: 'probe', method: 'POST', pathAndQuery: '/api/wallets/acct_a/deposit', actor: ACTORS.memberA, requestJson: { balance: 25 }, json: { balance: 25 } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: 25 } }),
      ],
    })
    assert.equal(depositBalanceKey.satisfied, false, depositBalanceKey.reason)

    // 3. Guessed post-balance alongside arithmetic operand `amount: 25` (100 + 25 = 125)
    const guessedPostBalance = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: 100 } }),
        makeStep({ id: 'p1', seq: 2, arm: 'probe', method: 'PATCH', pathAndQuery: '/api/wallets/acct_a', actor: ACTORS.memberA, requestJson: { amount: 25, balance: 125 }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: 125 } }),
      ],
    })
    assert.equal(guessedPostBalance.satisfied, false, guessedPostBalance.reason)

    // 4. Honest seat/credits counter increment
    const seatAdd = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/orgs/org_a/seats', actor: ACTORS.ownerA, json: { id: 'org_a', seats_used: 0 } }),
        makeStep({ id: 'a1', seq: 2, arm: 'probe', method: 'POST', pathAndQuery: '/api/orgs/org_a/add', actor: ACTORS.ownerA, requestJson: { delta: 1 }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/orgs/org_a/seats', actor: ACTORS.ownerA, json: { id: 'org_a', seats_used: 1 } }),
      ],
    })
    assert.equal(seatAdd.satisfied, false, seatAdd.reason)
  })

  test('preserves genuine business_logic TPs (direct PATCH tamper, double-withdraw floor crossing on sibling routes, single-step overdraft bound, declared price tamper)', () => {
    // 1. Direct PATCH overwrite of protected balance (arbitrary tamper 100 -> 999)
    const directTamper = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a', actor: ACTORS.memberA, json: { id: 'acct_a', balance: 100 } }),
        makeStep({ id: 'p1', seq: 2, arm: 'probe', method: 'PATCH', pathAndQuery: '/api/wallets/acct_a', actor: ACTORS.memberA, requestJson: { balance: 999 }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a', actor: ACTORS.memberA, json: { id: 'acct_a', balance: 999 } }),
      ],
    })
    assert.equal(directTamper.satisfied, true, directTamper.reason)

    // 2. Repeated double-withdraw across sibling /balance + /withdraw routes crossing floor=0
    const doubleWithdraw = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      invariantBounds: [{ field: 'balance', kind: 'floor', min: 0 }],
      steps: [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: 100 } }),
        makeStep({ id: 'w1', seq: 2, arm: 'probe', method: 'POST', pathAndQuery: '/api/wallets/acct_a/withdraw', actor: ACTORS.memberA, requestJson: { amount: 60 }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: 40 } }),
        makeStep({ id: 'w2', seq: 4, arm: 'probe', method: 'POST', pathAndQuery: '/api/wallets/acct_a/withdraw', actor: ACTORS.memberA, requestJson: { amount: 60 }, json: { ok: true } }),
        makeStep({ id: 'r2', seq: 5, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: -20 } }),
      ],
    })
    assert.equal(doubleWithdraw.satisfied, true, doubleWithdraw.reason)
    assert.equal(doubleWithdraw.evidence.repeatedTransition, true)
    assert.equal(doubleWithdraw.evidence.boundCrossed, true)

    // 3. Single-step overdraft crossing declared floor=0
    const singleOverdraft = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      invariantBounds: [{ field: 'balance', kind: 'floor', min: 0 }],
      steps: [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: 100 } }),
        makeStep({ id: 'w1', seq: 2, arm: 'probe', method: 'POST', pathAndQuery: '/api/wallets/acct_a/withdraw', actor: ACTORS.memberA, requestJson: { amount: 150 }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: -50 } }),
      ],
    })
    assert.equal(singleOverdraft.satisfied, true, singleOverdraft.reason)
    assert.equal(singleOverdraft.evidence.boundCrossed, true)

    // 4. Price tamper with declared invariant oracle event
    const priceTamper = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      oracleEvents: ['invariant_violation'],
      steps: [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/billing/plan', actor: ACTORS.ownerA, json: { plan: 'pro', price: 4900 } }),
        makeStep({ id: 'p1', seq: 2, arm: 'probe', method: 'PATCH', pathAndQuery: '/api/billing/plan', actor: ACTORS.ownerA, requestJson: { price: 1 }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/billing/plan', actor: ACTORS.ownerA, json: { plan: 'pro', price: 1 } }),
      ],
    })
    assert.equal(priceTamper.satisfied, true, priceTamper.reason)

    // 5. T2: Direct overwrite of credits 0 -> 500 is NOT self-explained as an arithmetic delta
    const directCreditsOverwrite = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/orgs/org_a', actor: ACTORS.memberA, json: { id: 'org_a', credits: 0 } }),
        makeStep({ id: 'p1', seq: 2, arm: 'probe', method: 'PATCH', pathAndQuery: '/api/orgs/org_a', actor: ACTORS.memberA, requestJson: { credits: 500 }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/orgs/org_a', actor: ACTORS.memberA, json: { id: 'org_a', credits: 500 } }),
      ],
    })
    assert.equal(directCreditsOverwrite.satisfied, true, directCreditsOverwrite.reason)

    // 6. T4: Reformatted numeric readback ("999.00" vs sent 999) still matches via finite numeric equality
    const reformattedNumericTamper = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a', actor: ACTORS.memberA, json: { id: 'acct_a', balance: '100.00' } }),
        makeStep({ id: 'p1', seq: 2, arm: 'probe', method: 'PATCH', pathAndQuery: '/api/wallets/acct_a', actor: ACTORS.memberA, requestJson: { balance: 999 }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a', actor: ACTORS.memberA, json: { id: 'acct_a', balance: '999.00' } }),
      ],
    })
    assert.equal(reformattedNumericTamper.satisfied, true, reformattedNumericTamper.reason)
  })

  test('R3-05 review B1/B2 guards: rejects server-derived protected leaf (tier promotion) and unattributed concurrent-writer bound crossings', () => {
    // B1: Honest deposit with echoed >=8-char reference moves balance 100->125 and server-derived tier silver->gold
    const derivedTier = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'before_bal', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.ownerA, json: { id: 'acct_a', balance: 100, tier: 'silver', last_reference: 'none' } }),
        makeStep({ id: 'prb_deposit', seq: 2, arm: 'probe', method: 'POST', pathAndQuery: '/api/wallets/acct_a/deposit', actor: ACTORS.ownerA, requestJson: { amount: 25, reference: 'dep-20260101-0001' }, json: { ok: true, reference: 'dep-20260101-0001' } }),
        makeStep({ id: 'after_bal', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.ownerA, json: { id: 'acct_a', balance: 125, tier: 'gold', last_reference: 'dep-20260101-0001' } }),
      ],
    })
    assert.equal(derivedTier.satisfied, false, `server-derived tier promotion must reject, got: ${derivedTier.reason}`)

    // B2: Concurrent/background writer moves balance across floor=0 while probe only sent an unrelated note
    const unattributedBound = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      invariantBounds: [{ field: 'balance', kind: 'floor', min: 0 }],
      steps: [
        makeStep({ id: 'r0', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: 100 } }),
        makeStep({ id: 'p1', seq: 2, arm: 'probe', method: 'POST', pathAndQuery: '/api/wallets/acct_a/note', actor: ACTORS.memberA, requestJson: { note: 'unrelated-probe-note' }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: -50 } }),
      ],
    })
    assert.equal(unattributedBound.satisfied, false, `unattributed concurrent-writer floor crossing must reject, got: ${unattributedBound.reason}`)

    // B2: Unattributed concurrent-writer overdraft even alongside a 409 refusal control
    const unattributedRefusal = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'ctl_409', seq: 1, arm: 'control', method: 'POST', pathAndQuery: '/api/wallets/acct_a/withdraw', status: 409, actor: ACTORS.memberA, requestJson: { amount: 25 }, json: { error: 'insufficient_funds' } }),
        makeStep({ id: 'r0', seq: 2, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: 100 } }),
        makeStep({ id: 'p1', seq: 3, arm: 'probe', method: 'POST', pathAndQuery: '/api/wallets/acct_a/withdraw', actor: ACTORS.memberA, requestJson: { amount: 25 }, json: { ok: true } }),
        makeStep({ id: 'r1', seq: 4, arm: 'control', method: 'GET', pathAndQuery: '/api/wallets/acct_a/balance', actor: ACTORS.memberA, json: { accountId: 'acct_a', balance: -37 } }),
      ],
    })
    assert.equal(unattributedRefusal.satisfied, false, `unattributed concurrent-writer overdraft must reject, got: ${unattributedRefusal.reason}`)
  })
})

describe('R3-12 FP #2: anon-401 login wall + owner-200 control never confirms same-tenant read', () => {
  test('rejects honest tenant-scoped object read across all authz/bfla/disclosure labels (doc_a1 and wallet balance)', () => {
    const scenarios = [
      {
        name: 'honest_rbac /api/docs/doc_a1',
        route: '/api/docs/doc_a1',
        payload: { id: 'doc_a1', tenant_id: 'tenant-a', owner: 'owner_a', title: 'Acme Quarterly Ledger', status: 'open' },
      },
      {
        name: 'honest_accumulator /api/wallets/acct_a/balance',
        route: '/api/wallets/acct_a/balance',
        payload: { accountId: 'acct_a', balance: 100, limit: 1000, owner: 'owner_a', tenant_id: 'tenant-a' },
      },
    ]

    for (const sc of scenarios) {
      const steps: ImpactStep[] = [
        makeStep({ id: 'ctl_owner', seq: 1, arm: 'control', method: 'GET', pathAndQuery: sc.route, status: 200, actor: ACTORS.ownerA, json: sc.payload }),
        makeStep({ id: 'ctl_anon', seq: 2, arm: 'control', method: 'GET', pathAndQuery: sc.route, status: 401, actor: ACTORS.anon, json: { error: 'authentication_required' } }),
        makeStep({ id: 'prb_foreign', seq: 3, arm: 'probe', method: 'GET', pathAndQuery: sc.route, status: 403, actor: ACTORS.ownerB, json: { error: 'forbidden_cross_tenant_access' } }),
        makeStep({ id: 'prb_viewer', seq: 4, arm: 'probe', method: 'GET', pathAndQuery: sc.route, status: 200, actor: ACTORS.viewerA, json: sc.payload }),
      ]

      // Direct assessor check across authorization, bfla, disclosure
      for (const impactClass of ['authorization', 'bfla', 'disclosure'] as const) {
        const assessment = assessAuthorizationImpact({ impactClass, steps })
        assert.equal(assessment.evidence.boundaryControlDenied, false, `${sc.name} (${impactClass}): anon 401 must never set boundaryControlDenied`)
        assert.equal(assessment.satisfied, false, `${sc.name} (${impactClass}) must reject, got: ${assessment.reason}`)
      }

      // Full verifyReceipt check across lateral sibling vulnClass labels
      const transcript = makeTranscript(steps)
      for (const vulnClass of ['bola', 'idor', 'cross_tenant_read', 'bfla', 'disclosure', 'broken_access_control']) {
        const receipt = buildProofReceipt({
          vulnClass,
          target: { origin: ORIGIN, method: 'GET', pathAndQuery: sc.route },
          exchangeIds: steps.map(s => s.id),
          claimedDelta: `Same-tenant read with anon-401 control claimed as ${vulnClass}.`,
        })
        const ver = verifyReceipt(receipt, transcript)
        assert.equal(ver.confirmed, false, `${sc.name} verifyReceipt(${vulnClass}) must reject, got: ${ver.reason}`)
      }
    }

    // Even when owner_b's 403 is placed in arm:'control' (cross-tenant isolation working), must still reject!
    const crossTenantCtrlSteps: ImpactStep[] = [
      makeStep({ id: 'ctl_owner', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/docs/doc_a1', status: 200, actor: ACTORS.ownerA, json: { id: 'doc_a1', tenant_id: 'tenant-a', owner: 'owner_a', title: 'Acme Quarterly Ledger' } }),
      makeStep({ id: 'ctl_anon', seq: 2, arm: 'control', method: 'GET', pathAndQuery: '/api/docs/doc_a1', status: 401, actor: ACTORS.anonCookie, json: { error: 'authentication_required' } }),
      makeStep({ id: 'ctl_foreign', seq: 3, arm: 'control', method: 'GET', pathAndQuery: '/api/docs/doc_a1', status: 403, actor: ACTORS.ownerB, json: { error: 'forbidden_cross_tenant_access' } }),
      makeStep({ id: 'prb_viewer', seq: 4, arm: 'probe', method: 'GET', pathAndQuery: '/api/docs/doc_a1', status: 200, actor: ACTORS.viewerA, json: { id: 'doc_a1', tenant_id: 'tenant-a', owner: 'owner_a', title: 'Acme Quarterly Ledger' } }),
    ]
    const receipt = buildProofReceipt({
      vulnClass: 'bola',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/docs/doc_a1' },
      exchangeIds: crossTenantCtrlSteps.map(s => s.id),
      claimedDelta: 'Cross-tenant 403 control + anon 401 control with same-tenant viewer 200.',
    })
    const ver = verifyReceipt(receipt, makeTranscript(crossTenantCtrlSteps))
    assert.equal(ver.confirmed, false, ver.reason)
  })

  test('preserves genuine cross-tenant BOLA reads (with or without anon-401 control), BFLA vertical, and unauthenticated bypass TPs', () => {
    // 1. Genuine cross-tenant BOLA read WITH anon-401 control + owner_a 200 control + owner_b 200 probe
    const crossTenantWithAnon: ImpactStep[] = [
      makeStep({ id: 'ctl_anon', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/invoices/inv_1', status: 401, actor: ACTORS.anon, json: { error: 'unauthenticated' } }),
      makeStep({ id: 'ctl_owner', seq: 2, arm: 'control', method: 'GET', pathAndQuery: '/api/invoices/inv_1', status: 200, actor: ACTORS.ownerA, json: { id: 'inv_1', tenant_id: 'tenant-a', owner_id: 'owner_a', amount_cents: 4200 } }),
      makeStep({ id: 'prb_cross', seq: 3, arm: 'probe', method: 'GET', pathAndQuery: '/api/invoices/inv_1', status: 200, actor: ACTORS.memberB, json: { id: 'inv_1', tenant_id: 'tenant-a', owner_id: 'owner_a', amount_cents: 4200 } }),
    ]
    const crossReceipt = buildProofReceipt({
      vulnClass: 'bola',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/invoices/inv_1' },
      exchangeIds: crossTenantWithAnon.map(s => s.id),
      claimedDelta: 'Tenant-B member read Tenant-A invoice.',
    })
    const crossVer = verifyReceipt(crossReceipt, makeTranscript(crossTenantWithAnon))
    assert.equal(crossVer.confirmed, true, `genuine cross-tenant BOLA read with anon 401 control must confirm, got: ${crossVer.reason}`)

    // 2. Genuine vertical BFLA with authenticated peer denial on privileged function surface
    const bflaSteps: ImpactStep[] = [
      makeStep({ id: 'ctl_member', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/admin/audit', status: 403, actor: ACTORS.memberA, json: { error: 'admin_only' } }),
      makeStep({ id: 'prb_viewer', seq: 2, arm: 'probe', method: 'GET', pathAndQuery: '/api/admin/audit', status: 200, actor: ACTORS.viewerA, json: { rows: [{ actor: 'admin', action: 'rotate-key' }] } }),
    ]
    const bflaReceipt = buildProofReceipt({
      vulnClass: 'bfla',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/admin/audit' },
      exchangeIds: bflaSteps.map(s => s.id),
      claimedDelta: 'Viewer read admin audit endpoint while member was denied 403.',
    })
    const bflaVer = verifyReceipt(bflaReceipt, makeTranscript(bflaSteps))
    assert.equal(bflaVer.confirmed, true, `genuine vertical BFLA must confirm, got: ${bflaVer.reason}`)

    // 3. Genuine unauthenticated bypass (bare anon 401 control vs anon + forged header 200 probe)
    const authBypassAssessment = assessAuthorizationImpact({
      impactClass: 'authorization',
      steps: [
        makeStep({ id: 'ctl_bare', seq: 1, arm: 'control', method: 'GET', pathAndQuery: '/api/docs/doc_a1', status: 401, actor: ACTORS.anon, json: { error: 'unauthenticated' } }),
        makeStep({ id: 'prb_hdr', seq: 2, arm: 'probe', method: 'GET', pathAndQuery: '/api/docs/doc_a1', status: 200, actor: ACTORS.anon, requestHeaders: { 'x-forwarded-user': 'admin' }, json: { id: 'doc_a1', owner_id: 'owner_a', email: 'owner@tenant-a.example', secret: 'top-secret' } }),
      ],
    })
    assert.equal(authBypassAssessment.evidence.boundaryControlDenied, true, 'unauthenticated bypass differential keeps boundaryControlDenied=true')
  })
})
