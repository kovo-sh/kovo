import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import {
  actorFromPersona,
  actorsAreCrossTenant,
  actorsShareTenant,
  assessAuthorizationImpact,
  parseRoleLabel,
  parseRoleMemberships,
  parseRoleTenants,
  type ActorIdentity,
  type ImpactStep,
} from '../src/server/oracle-invariants.ts'
import { personaPicks, type EnginePersona } from '../src/server/deterministic-engine.ts'
import { floorActorFor } from '../src/server/floor-recipe-engine.ts'

function makeActor(
  handle: string,
  role: ActorIdentity['role'],
  tenant: string | null,
  tenants?: readonly string[],
): ActorIdentity {
  return {
    handle,
    role,
    tenant,
    ...(tenants ? { tenants } : {}),
    auth: 'bearer',
    sameSite: null,
  }
}

describe('v8 same-tenant BOLA precision and role@tenant identity parsing', () => {
  test('parseRoleLabel and parseRoleTenants handle role@tenant, multi-tenant lists, parenthetical labels, and ignore raw emails', () => {
    assert.deepEqual(parseRoleLabel('owner@org_a'), { role: 'owner', tenant: 'org_a' })
    assert.deepEqual(parseRoleLabel('member@org_b'), { role: 'member', tenant: 'org_b' })
    assert.deepEqual(parseRoleLabel('viewer@org_a'), { role: 'viewer', tenant: 'org_a' })
    assert.deepEqual(parseRoleLabel('owner (acme)'), { role: 'owner', tenant: 'acme' })
    assert.deepEqual(parseRoleLabel('admin@org_a, viewer@org_b'), { role: 'admin', tenant: 'org_a' })
    assert.deepEqual(parseRoleTenants('admin@org_a, viewer@org_b'), ['org_a', 'org_b'])
    assert.deepEqual(parseRoleMemberships('admin@org_a, viewer@org_b'), [
      { role: 'admin', tenant: 'org_a' },
      { role: 'viewer', tenant: 'org_b' },
    ])
    // Bracketed metadata with parenthetical primary tenant + memberships list.
    assert.deepEqual(
      parseRoleLabel('admin [slug=acme; memberships=admin:org_a,viewer:org_b] (org_a)'),
      { role: 'admin', tenant: 'org_a' },
    )
    assert.deepEqual(
      parseRoleTenants('admin [slug=acme; memberships=admin:org_a,viewer:org_b] (org_a)'),
      ['org_a', 'org_b'],
    )
    // Raw email address whose local part is not a role word must not be misparsed as a tenant.
    assert.deepEqual(parseRoleLabel('alice@example.com'), { role: null, tenant: null })
    assert.deepEqual(parseRoleTenants('alice@example.com'), [])
  })

  test('actorFromPersona preserves multi-tenant memberships for overlap and cross-tenant checks', () => {
    const personas = [
      { handle: 'owner_a', roleLabel: 'owner@org_a', authKind: 'bearer' },
      { handle: 'member_a', roleLabel: 'member@org_a', authKind: 'bearer' },
      { handle: 'dual_member', roleLabel: 'admin@org_a, viewer@org_b', authKind: 'bearer' },
      { handle: 'member_b', roleLabel: 'member@org_b', authKind: 'bearer' },
    ]
    const ownerA = actorFromPersona('owner_a', personas)
    const memberA = actorFromPersona('member_a', personas)
    const dual = actorFromPersona('dual_member', personas)
    const memberB = actorFromPersona('member_b', personas)

    assert.equal(ownerA.tenant, 'org_a')
    assert.equal(ownerA.role, 'owner')
    assert.deepEqual(dual.tenants, ['org_a', 'org_b'])
    assert.equal(actorsShareTenant(ownerA, memberA), true)
    assert.equal(actorsShareTenant(ownerA, dual), true)
    assert.equal(actorsShareTenant(memberB, dual), true)
    assert.equal(actorsAreCrossTenant(ownerA, dual), false)
    assert.equal(actorsAreCrossTenant(memberB, dual), false)
    assert.equal(actorsAreCrossTenant(ownerA, memberB), true)
  })

  test('personaPicks pairs only strictly disjoint cross-tenant personas and never pairs same-tenant peers', () => {
    // Multi-tenant SaaS where EnginePersona.tenant was left undefined by a caller that only parsed `(tenant)`.
    const multiTenantPersonas: EnginePersona[] = [
      { handle: 'owner_a', roleLabel: 'owner@org_a', privilege: 'owner' },
      { handle: 'member_a', roleLabel: 'member@org_a', privilege: 'member' },
      { handle: 'viewer_a', roleLabel: 'viewer@org_a', privilege: 'viewer' },
      { handle: 'dual_member', roleLabel: 'admin@org_a, viewer@org_b', privilege: 'admin' },
      { handle: 'member_b', roleLabel: 'member@org_b', privilege: 'member' },
    ]
    const picks = personaPicks(multiTenantPersonas)
    assert.equal(picks.owner?.handle, 'owner_a')
    assert.equal(picks.crossTenant?.handle, 'member_b', 'must skip member_a, viewer_a, and dual_member to pick disjoint org_b')
    assert.equal(picks.lower?.handle, 'viewer_a')

    // When all seeded personas belong to the SAME tenant, crossTenant must stay undefined.
    const sameTenantOnly: EnginePersona[] = [
      { handle: 'owner_a', roleLabel: 'owner@org_a', privilege: 'owner' },
      { handle: 'member_a', roleLabel: 'member@org_a', privilege: 'member' },
      { handle: 'viewer_a', roleLabel: 'viewer@org_a', privilege: 'viewer' },
    ]
    const samePicks = personaPicks(sameTenantOnly)
    assert.equal(samePicks.owner?.handle, 'owner_a')
    assert.equal(samePicks.crossTenant, undefined, 'must never pair same-tenant personas as cross-tenant BOLA')
    assert.equal(samePicks.lower?.handle, 'viewer_a')

    // Single-tenant user-vs-user app with no tenant metadata retains user1/user2 pairing.
    const untenantPersonas: EnginePersona[] = [
      { handle: 'user_a', roleLabel: 'member', privilege: 'member' },
      { handle: 'user_b', roleLabel: 'member', privilege: 'member' },
    ]
    const untenantPicks = personaPicks(untenantPersonas)
    assert.equal(untenantPicks.owner?.handle, 'user_a')
    assert.equal(untenantPicks.crossTenant?.handle, 'user_b')

    // floorActorFor resolves role and tenant from role@tenant when EnginePersona.tenant is absent.
    const floorOwner = floorActorFor('owner_a', multiTenantPersonas)
    assert.equal(floorOwner.role, 'owner')
    assert.equal(floorOwner.tenant, 'org_a')
  })

  test('same-tenant reads of org-shared resources fail closed even with amountCents, createdBy, bogus-ID 404, and Org B 403', () => {
    const ownerA = makeActor('owner_a', 'owner', 'org_a')
    const memberA = makeActor('member_a', 'member', 'org_a')
    const viewerA = makeActor('viewer_a', 'viewer', 'org_a')
    const dual = makeActor('dual_member', 'admin', 'org_a', ['org_a', 'org_b'])
    const memberB = makeActor('member_b', 'member', 'org_b')

    const invoicePayload = {
      invoice: {
        id: 'inv_1001',
        tenantId: 'org_a',
        templateId: 'tpl_1',
        amountCents: 42000,
        status: 'open',
      },
    }
    const payoutPayload = {
      payout: {
        id: 'pay_2001',
        tenantId: 'org_a',
        amountCents: 75000,
        beneficiary: 'acct_vendor_1',
        status: 'draft',
        createdBy: 'usr_owner_a',
      },
    }

    // 1. owner_a + member_a in Org A reading an Org A invoice (with bogus-ID 404 + Org B 403 control) -> 0 FPs.
    const sameTenantInvoice = assessAuthorizationImpact({
      impactClass: 'authorization',
      steps: [
        { id: 'c_owner', arm: 'control', method: 'GET', route: '/v1/invoices/:id', pathAndQuery: '/v1/invoices/inv_1001', status: 200, actor: ownerA, json: invoicePayload },
        { id: 'c_bogus', arm: 'control', method: 'GET', route: '/v1/invoices/:id', pathAndQuery: '/v1/invoices/inv_nonexistent', status: 404, actor: ownerA, json: { error: 'unknown invoice' } },
        { id: 'c_org_b', arm: 'control', method: 'GET', route: '/v1/invoices/:id', pathAndQuery: '/v1/invoices/inv_1001', status: 403, actor: memberB, json: { error: 'forbidden' } },
        { id: 'p_member', arm: 'probe', method: 'GET', route: '/v1/invoices/:id', pathAndQuery: '/v1/invoices/inv_1001', status: 200, actor: memberA, json: invoicePayload },
      ],
    })
    assert.equal(sameTenantInvoice.satisfied, false, `Expected same-tenant invoice read to fail closed, got: ${sameTenantInvoice.reason}`)
    assert.equal(sameTenantInvoice.evidence.boundaryControlDenied, false)
    assert.equal(sameTenantInvoice.evidence.crossTenant, false)

    // 2. owner_a + viewer_a in Org A reading an Org A payout with createdBy + amountCents -> 0 FPs.
    const sameTenantPayout = assessAuthorizationImpact({
      impactClass: 'authorization',
      steps: [
        { id: 'c_owner', arm: 'control', method: 'GET', route: '/v1/payouts/:id', pathAndQuery: '/v1/payouts/pay_2001', status: 200, actor: ownerA, json: payoutPayload },
        { id: 'c_bogus', arm: 'control', method: 'GET', route: '/v1/payouts/:id', pathAndQuery: '/v1/payouts/pay_nonexistent', status: 404, actor: ownerA, json: { error: 'unknown payout' } },
        { id: 'p_viewer', arm: 'probe', method: 'GET', route: '/v1/payouts/:id', pathAndQuery: '/v1/payouts/pay_2001', status: 200, actor: viewerA, json: payoutPayload },
      ],
    })
    assert.equal(sameTenantPayout.satisfied, false, `Expected same-tenant payout read to fail closed, got: ${sameTenantPayout.reason}`)

    // 3. dual_member (admin@org_a, viewer@org_b) reading Org A payout alongside owner_a -> 0 FPs.
    const dualMemberRead = assessAuthorizationImpact({
      impactClass: 'authorization',
      steps: [
        { id: 'c_owner', arm: 'control', method: 'GET', route: '/v1/payouts/:id', pathAndQuery: '/v1/payouts/pay_2001', status: 200, actor: ownerA, json: payoutPayload },
        { id: 'p_dual', arm: 'probe', method: 'GET', route: '/v1/payouts/:id', pathAndQuery: '/v1/payouts/pay_2001', status: 200, actor: dual, json: payoutPayload },
      ],
    })
    assert.equal(dualMemberRead.satisfied, false, `Expected dual-member intra-tenant read to fail closed, got: ${dualMemberRead.reason}`)
  })

  test('genuine cross-tenant BOLA, single-tenant user-vs-user BOLA, and same-tenant secret leaks still confirm at 100% recall', () => {
    const ownerA = makeActor('owner_a', 'owner', 'org_a')
    const memberA = makeActor('member_a', 'member', 'org_a')
    const memberB = makeActor('member_b', 'member', 'org_b')

    const invoicePayload = {
      invoice: {
        id: 'inv_1001',
        tenantId: 'org_a',
        amountCents: 42000,
        status: 'open',
      },
    }

    // 1. Genuine cross-tenant BOLA: Org B member_b reads Org A's invoice -> CONFIRMED.
    const crossTenantSteps: ImpactStep[] = [
      { id: 'c_owner', arm: 'control', method: 'GET', route: '/v1/invoices/:id', pathAndQuery: '/v1/invoices/inv_1001', status: 200, actor: ownerA, json: invoicePayload },
      { id: 'c_bogus', arm: 'control', method: 'GET', route: '/v1/invoices/:id', pathAndQuery: '/v1/invoices/inv_nonexistent', status: 404, actor: ownerA, json: { error: 'unknown invoice' } },
      { id: 'p_org_b', arm: 'probe', method: 'GET', route: '/v1/invoices/:id', pathAndQuery: '/v1/invoices/inv_1001', status: 200, actor: memberB, json: invoicePayload },
    ]
    const crossTenantVerdict = assessAuthorizationImpact({ impactClass: 'authorization', steps: crossTenantSteps })
    assert.equal(crossTenantVerdict.satisfied, true, crossTenantVerdict.reason)
    assert.equal(crossTenantVerdict.evidence.crossTenant, true)

    // 2. Genuine single-tenant user-vs-user BOLA (no tenant metadata) -> CONFIRMED.
    const userA = makeActor('user_a', 'member', null)
    const userB = makeActor('user_b', 'member', null)
    const singleTenantBola = assessAuthorizationImpact({
      impactClass: 'authorization',
      steps: [
        { id: 'c1', arm: 'control', method: 'GET', route: '/api/orders/:id', pathAndQuery: '/api/orders/42', status: 200, actor: userA, json: { id: '42', owner_id: 'user_a', email: 'alice@example.test', total: 4900 } },
        { id: 'c2', arm: 'control', method: 'GET', route: '/api/orders/:id', pathAndQuery: '/api/orders/999999', status: 404, actor: userA, json: { error: 'not_found' } },
        { id: 'p1', arm: 'probe', method: 'GET', route: '/api/orders/:id', pathAndQuery: '/api/orders/42', status: 200, actor: userB, json: { id: '42', owner_id: 'user_a', email: 'alice@example.test', total: 4900 } },
      ],
    })
    assert.equal(singleTenantBola.satisfied, true, singleTenantBola.reason)

    // 3. Genuine same-tenant secret/credential disclosure -> CONFIRMED.
    const sameTenantSecret = assessAuthorizationImpact({
      impactClass: 'authorization',
      steps: [
        { id: 'c1', arm: 'control', method: 'GET', route: '/api/keys/:id', pathAndQuery: '/api/keys/k1', status: 200, actor: ownerA, json: { id: 'k1', tenantId: 'org_a', api_key: 'sk_live_synthetic_123456' } },
        { id: 'p1', arm: 'probe', method: 'GET', route: '/api/keys/:id', pathAndQuery: '/api/keys/k1', status: 200, actor: memberA, json: { id: 'k1', tenantId: 'org_a', api_key: 'sk_live_synthetic_123456' } },
      ],
    })
    assert.equal(sameTenantSecret.satisfied, true, sameTenantSecret.reason)
  })
})
