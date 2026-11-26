import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, test } from 'node:test'

import { normalizeConfirmedRouteTemplate } from '../src/server/exec-recon-planner.ts'
import {
  planChainRound,
  structuralTransitionFeasibility,
  type CausalPlanUnit,
} from '../src/server/graph-coordinator.ts'
import {
  assessAuthorizationImpact,
  clearRegisteredCanaryMarkers,
  hasForeignTenantOrOwnerDisclosure,
  registerCanaryMarker,
  type ImpactStep,
} from '../src/server/oracle-invariants.ts'
import { normalizeDiscoveryTemplate } from '../src/server/phase0-recon.ts'
import { normalizeRouteTemplate } from '../src/server/route-template.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)

function makeCausalUnit(overrides: Partial<CausalPlanUnit>): CausalPlanUnit {
  return {
    unitId: 'u1',
    capId: 'cap:hop_1:tok',
    capKind: 'identity_session',
    primitive: {
      kind: 'leaked_token',
      origin: 'https://api.example.invalid',
      value: 'cap:hop_1:tok',
      evidenceIds: [],
      factIds: [],
      endpoint: '/api/session',
      method: 'GET',
      detail: 'session token',
    },
    surface: 'http',
    tenantScope: null,
    actorPersona: 'member_a',
    serviceOrigin: 'https://api.example.invalid',
    hopReceiptId: 'hop-1',
    verified: true,
    quarantined: false,
    terminalEligible: true,
    targetSurfaceKey: 'https://api.example.invalid|http|/api/session',
    hypothesisClass: 'broken-access-control',
    endpoint: '/api/session',
    method: 'GET',
    ...overrides,
  }
}

describe('Wave A #4: canonical normalizeRouteTemplate', () => {
  test('normalizes UUIDs, ULIDs, numeric IDs, hex/base64url tokens, prefixed IDs, and framework param templates', () => {
    assert.equal(normalizeRouteTemplate('/api/users/42'), '/api/users/:id')
    assert.equal(
      normalizeRouteTemplate('/api/orders/550e8400-e29b-41d4-a716-446655440000'),
      '/api/orders/:id',
    )
    assert.equal(
      normalizeRouteTemplate('/api/orders/01ARZ3NDEKTSV4RRFFQ69G5FAV'),
      '/api/orders/:id',
    )
    assert.equal(normalizeRouteTemplate('/api/items/507f1f77bcf86cd799439011'), '/api/items/:id')
    assert.equal(normalizeRouteTemplate('/api/tokens/eyJhbGciOiJIUzI1NiJ9_abc123'), '/api/tokens/:id')
    assert.equal(normalizeRouteTemplate('/api/users/usr_123'), '/api/users/:id')
    assert.equal(normalizeRouteTemplate('/api/invoices/inv_abcd'), '/api/invoices/:id')
    assert.equal(normalizeRouteTemplate('/api/invoices/inv_9a2f?expand=lines'), '/api/invoices/:id')
    assert.equal(normalizeRouteTemplate('/api/orders/ord-1001/items/itm_01'), '/api/orders/:id/items/:id')

    // Express / OpenAPI / Next.js / Django param templates
    assert.equal(normalizeRouteTemplate('/api/users/:userId'), '/api/users/:id')
    assert.equal(normalizeRouteTemplate('/api/users/{userId}'), '/api/users/:id')
    assert.equal(normalizeRouteTemplate('/api/users/[userId]'), '/api/users/:id')
    assert.equal(normalizeRouteTemplate('/api/docs/[...slug]'), '/api/docs/:id')
    assert.equal(normalizeRouteTemplate('/api/users/<int:user_id>'), '/api/users/:id')
    assert.equal(normalizeRouteTemplate('/api/users/<id>/'), '/api/users/:id')

    // Preserves named params when requested (ProgramGraph / discovery)
    assert.equal(
      normalizeRouteTemplate('/api/orgs/{orgId}/users/<int:user_id>', {
        preserveParamNames: true,
        collapseConcreteIds: false,
      }),
      '/api/orgs/:orgId/users/:user_id',
    )
    assert.equal(
      normalizeDiscoveryTemplate('/api/orgs/:orgId/invoices/:invoiceId'),
      '/api/orgs/:orgId/invoices/:invoiceId',
    )
    assert.equal(normalizeDiscoveryTemplate('/api/items/<int:id>/view/'), '/api/items/:id/view')

    // Preserves static route words, versions, and protocol names
    assert.equal(normalizeRouteTemplate('/api/v1/user-profile'), '/api/v1/user-profile')
    assert.equal(normalizeRouteTemplate('/api/v2/reset-password'), '/api/v2/reset-password')
    assert.equal(normalizeRouteTemplate('/api/v1/oauth2/token'), '/api/v1/oauth2/token')
    assert.equal(normalizeRouteTemplate('/api/api-v2/health-check'), '/api/api-v2/health-check')
    assert.equal(normalizeRouteTemplate('/api/v1/user_feed'), '/api/v1/user_feed')
    assert.equal(normalizeRouteTemplate('/trpc/user.getById'), '/trpc/user.getById')

    // Parity with planner normalizer (case-insensitive mode)
    assert.equal(
      normalizeConfirmedRouteTemplate('/api/Users/usr_123'),
      normalizeRouteTemplate('/api/Users/usr_123', { preserveCase: false }),
    )
  })

  test('phase0-recon, program-graph, and exec-recon-planner import canonical normalizeRouteTemplate without duplicates', () => {
    const phase0 = readFileSync(resolve(REPO_ROOT, 'src/server/phase0-recon.ts'), 'utf8')
    const graph = readFileSync(resolve(REPO_ROOT, 'src/server/program-graph.ts'), 'utf8')
    const planner = readFileSync(resolve(REPO_ROOT, 'src/server/exec-recon-planner.ts'), 'utf8')

    assert.match(phase0, /from '\.\/route-template\.ts'/)
    assert.match(graph, /from '\.\/route-template\.ts'/)
    assert.match(planner, /from '\.\/route-template\.ts'/)

    assert.equal(/function normalizeRouteTemplate\(/.test(phase0), false)
    assert.equal(/function normalizePathTemplate\(/.test(graph), false)
    assert.equal(/SHORT_PREFIXED_DIGIT_ID_RE/.test(planner), false)
  })
})

describe('Wave A #2b: nullable tenantScope and origin fallback removal', () => {
  test('structuralTransitionFeasibility does not collapse null tenants or treat null as cross-tenant', () => {
    const nullUnits: CausalPlanUnit[] = [
      makeCausalUnit({ unitId: 'u1', capId: 'cap:hop_1:a', capKind: 'identity_session', tenantScope: null }),
      makeCausalUnit({
        unitId: 'u2',
        capId: 'cap:hop_2:b',
        capKind: 'state_handle',
        surface: 'async_job',
        tenantScope: null,
      }),
    ]
    const mixedKnownAndNull: CausalPlanUnit[] = [
      makeCausalUnit({ unitId: 'u1', capId: 'cap:hop_1:a', capKind: 'identity_session', tenantScope: 'org_a' }),
      makeCausalUnit({
        unitId: 'u2',
        capId: 'cap:hop_2:b',
        capKind: 'state_handle',
        surface: 'async_job',
        tenantScope: null,
      }),
    ]
    const twoKnownTenants: CausalPlanUnit[] = [
      makeCausalUnit({ unitId: 'u1', capId: 'cap:hop_1:a', capKind: 'identity_session', tenantScope: 'org_a' }),
      makeCausalUnit({
        unitId: 'u2',
        capId: 'cap:hop_2:b',
        capKind: 'state_handle',
        surface: 'async_job',
        tenantScope: 'org_b',
      }),
    ]

    const nullScore = structuralTransitionFeasibility(nullUnits, 1)
    const mixedScore = structuralTransitionFeasibility(mixedKnownAndNull, 1)
    const crossTenantScore = structuralTransitionFeasibility(twoKnownTenants, 1)

    assert.equal(nullScore.terminalImpactWeight, mixedScore.terminalImpactWeight)
    assert.ok(
      crossTenantScore.terminalImpactWeight > mixedScore.terminalImpactWeight,
      'only two distinct non-null tenants should receive the cross-tenant impact boost',
    )
  })

  test('planChainRound never synthesizes https://target.local when no real origin is provided', () => {
    const planned = planChainRound({
      primitives: [],
      endpoints: [],
      apiDependencies: [
        { producer: 'POST /api/orders', consumer: 'GET /api/orders/:id', resourceKey: 'orderId' },
      ],
    })
    assert.equal(planned.length, 0)
  })

  test('graph-coordinator and exec-recon-planner contain zero default_tenant or target.local literals', () => {
    const coordinator = readFileSync(resolve(REPO_ROOT, 'src/server/graph-coordinator.ts'), 'utf8')
    const planner = readFileSync(resolve(REPO_ROOT, 'src/server/exec-recon-planner.ts'), 'utf8')

    assert.equal(coordinator.includes('default_tenant'), false)
    assert.equal(coordinator.includes('target.local'), false)
    assert.equal(planner.includes('default_tenant'), false)
  })
})

describe('Wave A #2b: oracle-invariants canary cleanup & generic marker matching', () => {
  test('oracle-invariants.ts contains zero leaked rbc_/rbs_ benchmark literals', () => {
    const src = readFileSync(resolve(REPO_ROOT, 'src/server/oracle-invariants.ts'), 'utf8')
    assert.equal(/rb\[cs\]_|rbc_|rbs_|CANARY_VALUE_RE/.test(src), false)
  })

  test('runtime-registered canary markers drive foreign-tenant disclosure and owner-bound checks', () => {
    const stepBase = (overrides: Partial<ImpactStep>): ImpactStep => ({
      id: 's1',
      arm: 'probe',
      method: 'GET',
      route: '/api/items',
      status: 200,
      actor: { handle: 'user_b', role: 'member', tenant: 'tenant_b', auth: 'cookie', sameSite: 'Lax' },
      ...overrides,
    })

    clearRegisteredCanaryMarkers()
    try {
      const marker = 'canary_tok_alpha_9911aa22'
      const probe = stepBase({ json: { items: [{ id: '1', note: `ref=${marker}` }] } })
      assert.equal(hasForeignTenantOrOwnerDisclosure([probe], probe), false)

      registerCanaryMarker({ value: marker, tenant: 'tenant_a' })
      assert.equal(hasForeignTenantOrOwnerDisclosure([probe], probe), true)

      const assessment = assessAuthorizationImpact({
        impactClass: 'authorization',
        steps: [probe],
      })
      assert.equal(assessment.satisfied, true, assessment.reason)
    } finally {
      clearRegisteredCanaryMarkers()
    }
  })

  test('ModelProfileSheet.tsx contains no hardcoded DeepSeek V4.1 Flash copy', () => {
    const sheet = readFileSync(resolve(REPO_ROOT, 'src/components/settings/ModelProfileSheet.tsx'), 'utf8')
    assert.equal(/DeepSeek V4\.1 Flash/i.test(sheet), false)
  })
})
