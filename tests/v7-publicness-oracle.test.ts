/**
 * v7 publicness oracle — regression tests for the `http_chain` CWE-639 publicness gap.
 *
 * Covers the structural shapes where a public storefront/content object (carrying plain display
 * attribution such as `author: "Jess"` and no owner-scoped principal or canary) was previously
 * misclassified as a cross-tenant BOLA read:
 *
 *  1. Same-route owner reference + cross-tenant item read with a plain display `author`.
 *  2. Multi-probe chain (`persona_a` list/read -> `persona_b` list/read) where `probe` steps
 *     include both the collection listing and the child item read.
 *  3. Collection-only control (`persona_a` list) -> cross-tenant item read (`persona_b` item)
 *     with no same-route owner reference, no denied control, and no principal/canary evidence.
 *  4. Anonymous 200 read alongside cross-tenant reads (`variantBody === anonBody`).
 *  5. Positive preservation: genuine private cross-tenant reads (owner_id, email, canary,
 *     principal-bound author, or denied control) still confirm cleanly.
 */
import assert from 'node:assert/strict'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { assessAuthorizationImpact, assessPublicness, type ImpactStep } from '../src/server/oracle-invariants.ts'
import { runCorpus } from '../scripts/smoke-agentic.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const CORPUS = join(repoRoot, 'benchmarks/realism-suite/traps/fp-archetypes.json')

const ownerA = { handle: 'persona_a', role: 'owner' as const, tenant: 'tenant-a', auth: 'cookie' as const, sameSite: 'lax' as const }
const ownerB = { handle: 'persona_b', role: 'owner' as const, tenant: 'tenant-b', auth: 'cookie' as const, sameSite: 'lax' as const }
const anon = { handle: null, role: null, tenant: null, auth: 'unknown' as const, sameSite: null }

const PUBLIC_ITEM = {
  id: 1,
  external_id: '628888',
  store_id: 'tenant-a',
  product_id: 1,
  author: 'Jess',
  body: '<p>Great quality</p>',
  approved: 1,
}

const LIST_A = {
  reviews: [{ external_id: '628888', product_id: 1, author: 'Jess', approved: 1 }],
}

const LIST_B = {
  reviews: [{ external_id: '771122', product_id: 2, author: 'Pat', approved: 1 }],
}

test('publicness: identical item read with plain display author is dismissed', () => {
  const steps: ImpactStep[] = [
    { id: 'c1', arm: 'control', method: 'GET', route: '/api/v1/items/:id', pathAndQuery: '/api/v1/items/628888', status: 200, actor: ownerA, json: PUBLIC_ITEM },
    { id: 'p1', arm: 'probe', method: 'GET', route: '/api/v1/items/:id', pathAndQuery: '/api/v1/items/628888', status: 200, actor: ownerB, json: PUBLIC_ITEM },
  ]
  const pub = assessPublicness({ steps, probe: steps[1]! })
  assert.equal(pub.public, true, pub.reason)

  const assessment = assessAuthorizationImpact({ impactClass: 'authorization', steps })
  assert.equal(assessment.satisfied, false, assessment.reason)
  assert.match(assessment.reason, /publicness/i)
})

test('publicness: multi-probe list-then-item chain inspects the child item read and dismisses', () => {
  const steps: ImpactStep[] = [
    { id: 'a_list', arm: 'control', method: 'GET', route: '/api/v1/items', pathAndQuery: '/api/v1/items', status: 200, actor: ownerA, json: LIST_A },
    { id: 'a_item', arm: 'control', method: 'GET', route: '/api/v1/items/:id', pathAndQuery: '/api/v1/items/628888', status: 200, actor: ownerA, json: PUBLIC_ITEM },
    { id: 'b_list', arm: 'probe', method: 'GET', route: '/api/v1/items', pathAndQuery: '/api/v1/items', status: 200, actor: ownerB, json: LIST_B },
    { id: 'b_item', arm: 'probe', method: 'GET', route: '/api/v1/items/:id', pathAndQuery: '/api/v1/items/628888', status: 200, actor: ownerB, json: PUBLIC_ITEM },
  ]
  const assessment = assessAuthorizationImpact({ impactClass: 'authorization', steps })
  assert.equal(assessment.satisfied, false, assessment.reason)
  assert.match(assessment.reason, /publicness/i)
})

test('publicness: parent-collection control only without same-route reference or principal/canary dismisses', () => {
  const steps: ImpactStep[] = [
    { id: 'a_list', arm: 'control', method: 'GET', route: '/api/v1/items', pathAndQuery: '/api/v1/items', status: 200, actor: ownerA, json: LIST_A },
    { id: 'b_item', arm: 'probe', method: 'GET', route: '/api/v1/items/:id', pathAndQuery: '/api/v1/items/628888', status: 200, actor: ownerB, json: PUBLIC_ITEM },
  ]
  const assessment = assessAuthorizationImpact({ impactClass: 'authorization', steps })
  assert.equal(assessment.satisfied, false, assessment.reason)
  assert.match(assessment.reason, /publicness/i)
})

test('publicness: anonymous 200 read on the same item route alongside cross-tenant probes dismisses', () => {
  const steps: ImpactStep[] = [
    { id: 'a_item', arm: 'control', method: 'GET', route: '/api/v1/items/:id', pathAndQuery: '/api/v1/items/628888', status: 200, actor: ownerA, json: PUBLIC_ITEM },
    { id: 'b_list', arm: 'probe', method: 'GET', route: '/api/v1/items', pathAndQuery: '/api/v1/items', status: 200, actor: ownerB, json: LIST_B },
    { id: 'b_item', arm: 'probe', method: 'GET', route: '/api/v1/items/:id', pathAndQuery: '/api/v1/items/628888', status: 200, actor: ownerB, json: PUBLIC_ITEM },
    { id: 'anon_item', arm: 'probe', method: 'GET', route: '/api/v1/items/:id', pathAndQuery: '/api/v1/items/628888', status: 200, actor: anon, json: PUBLIC_ITEM },
  ]
  const assessment = assessAuthorizationImpact({ impactClass: 'authorization', steps })
  assert.equal(assessment.satisfied, false, assessment.reason)
  assert.match(assessment.reason, /publicness/i)
})

test('positive: genuine private cross-tenant reads still confirm (owner_id, email, canary, principal-bound author)', () => {
  // 1. Principal ownership field (`owner_id`)
  const byOwnerId = assessAuthorizationImpact({
    impactClass: 'authorization',
    steps: [
      { id: 'c1', arm: 'control', method: 'GET', route: '/api/v1/docs/:id', pathAndQuery: '/api/v1/docs/1', status: 200, actor: ownerA, json: { id: '1', owner_id: 'persona_a', title: 'Private' } },
      { id: 'p1', arm: 'probe', method: 'GET', route: '/api/v1/docs/:id', pathAndQuery: '/api/v1/docs/1', status: 200, actor: ownerB, json: { id: '1', owner_id: 'persona_a', title: 'Private' } },
    ],
  })
  assert.equal(byOwnerId.satisfied, true, byOwnerId.reason)

  // 2. Customer PII (`email`) even when control is parent-collection only
  const byEmail = assessAuthorizationImpact({
    impactClass: 'authorization',
    steps: [
      { id: 'c_list', arm: 'control', method: 'GET', route: '/api/v1/customers', pathAndQuery: '/api/v1/customers', status: 200, actor: ownerA, json: { customers: [{ id: '10' }] } },
      { id: 'p_item', arm: 'probe', method: 'GET', route: '/api/v1/customers/:id', pathAndQuery: '/api/v1/customers/10', status: 200, actor: ownerB, json: { id: '10', name: 'Dana', email: 'dana@tenant-a.test' } },
    ],
  })
  assert.equal(byEmail.satisfied, true, byEmail.reason)

  // 3. Tenant canary in a ticket/record with `subject`
  const byCanary = assessAuthorizationImpact({
    impactClass: 'authorization',
    steps: [
      { id: 'c1', arm: 'control', method: 'GET', route: '/api/v1/tickets/:id', pathAndQuery: '/api/v1/tickets/5', status: 200, actor: ownerA, json: { ext_id: '5', subject: 'Billing', body: 'ref rbc_tenanta_0123456789ab' } },
      { id: 'p1', arm: 'probe', method: 'GET', route: '/api/v1/tickets/:id', pathAndQuery: '/api/v1/tickets/5', status: 200, actor: ownerB, json: { ext_id: '5', subject: 'Billing', body: 'ref rbc_tenanta_0123456789ab' } },
    ],
  })
  assert.equal(byCanary.satisfied, true, byCanary.reason)

  // 4. `author` explicitly carrying an email address or owner handle still defeats publicness
  const byEmailAuthor = assessAuthorizationImpact({
    impactClass: 'authorization',
    steps: [
      { id: 'c1', arm: 'control', method: 'GET', route: '/api/v1/notes/:id', pathAndQuery: '/api/v1/notes/9', status: 200, actor: ownerA, json: { id: '9', author: 'alice@tenant-a.test', body: 'internal' } },
      { id: 'p1', arm: 'probe', method: 'GET', route: '/api/v1/notes/:id', pathAndQuery: '/api/v1/notes/9', status: 200, actor: ownerB, json: { id: '9', author: 'alice@tenant-a.test', body: 'internal' } },
    ],
  })
  assert.equal(byEmailAuthor.satisfied, true, byEmailAuthor.reason)

  // 5. Parent-collection control + denied anonymous control (401) proves the route is gated
  const byDeniedControl = assessAuthorizationImpact({
    impactClass: 'authorization',
    steps: [
      { id: 'c_list', arm: 'control', method: 'GET', route: '/api/v1/records', pathAndQuery: '/api/v1/records', status: 200, actor: ownerA, json: { items: [{ id: '1' }] } },
      { id: 'c_anon', arm: 'control', method: 'GET', route: '/api/v1/records/:id', pathAndQuery: '/api/v1/records/1', status: 401, actor: anon, json: { error: 'auth_required' } },
      { id: 'p_item', arm: 'probe', method: 'GET', route: '/api/v1/records/:id', pathAndQuery: '/api/v1/records/1', status: 200, actor: ownerB, json: { id: '1', summary: 'gated record' } },
    ],
  })
  assert.equal(byDeniedControl.satisfied, true, byDeniedControl.reason)
})

test('tier0 corpus includes and dismisses public-item-attribution-read', () => {
  const { results, pass } = runCorpus(CORPUS)
  assert.equal(pass, true, results.filter(r => !r.dismissed).map(r => `${r.id}: ${r.reason}`).join('; '))
  const entry = results.find(r => r.id === 'public-item-attribution-read')
  assert.ok(entry, 'public-item-attribution-read must be present in the Tier-0 FP corpus')
  assert.equal(entry.dismissed, true, entry.reason)
  assert.match(entry.reason, /publicness/i)
})
