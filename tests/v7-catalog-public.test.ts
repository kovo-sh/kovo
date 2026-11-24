/**
 * v7 catalog-public — the recurrent over-claim family on shopflow storefront catalog reads.
 *
 * Three independent runs confirmed the same family while grading unmatched:
 *   GET /api/v1/catalog                              (listProducts)
 *   GET /api/v1/catalog/:productId                   (getProduct)
 *   GET /api/v1/stores/:storeId/catalog/:productId   (storeProductPage)
 *
 * Truth ruling (from the fixture source, see benchmarks/CHANGELOG.md): all three are intended
 * *public* storefront reads. `storeProductPage` is the planted cache-poisoning surface, but its
 * anonymous arm must never resolve a customer loyalty-note canary. The dismissal rule is evidence
 * based: an anonymous/non-owner response identical to the owner reference (or differing only in
 * fields the public listing already exposes) is publicness, not an access-control crossing.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { assessAuthorizationImpact, type ImpactStep } from '../src/server/oracle-invariants.ts'
import { createCanaryRegistry } from '../benchmarks/realistic-bench/lib/canary.ts'
import { createResponseCache, detectCachePoison } from '../benchmarks/realistic-bench/lib/http-cache.ts'
import type { Oracle } from '../benchmarks/realistic-bench/lib/oracle.ts'
import type { AppContext } from '../benchmarks/realistic-bench/apps/shopflow/src/context.ts'
import registerStorePage from '../benchmarks/realistic-bench/apps/shopflow/sites/storefront-cache-poison/vulnerable.ts'
import { loadCorpus, runCorpus } from '../scripts/smoke-agentic.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const CORPUS = join(repoRoot, 'benchmarks/realism-suite/traps/fp-archetypes.json')

const STORE_A = '9ca676'
const STORE_B = '6ea2e7'

const ownerA = { handle: 'persona_a', role: 'owner' as const, tenant: STORE_A, auth: 'cookie' as const, sameSite: 'lax' as const }
const ownerB = { handle: 'persona_b', role: 'owner' as const, tenant: STORE_B, auth: 'cookie' as const, sameSite: 'lax' as const }
const anon = { handle: null, role: null, tenant: null, auth: 'unknown' as const, sameSite: null }

function step(over: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status' | 'actor'>): ImpactStep {
  return { route: '/api/v1/catalog', ...over }
}

// ---------------------------------------------------------------------------
// 1. Tier-0: the archetype family replays with no model and is dismissed
// ---------------------------------------------------------------------------

test('tier0: the catalog-public archetypes all dismiss (no model, no worker)', () => {
  const { results, pass } = runCorpus(CORPUS)
  assert.equal(pass, true, results.filter(r => !r.dismissed).map(r => `${r.id}: ${r.reason}`).join('; '))
  const ids = ['catalog-canary-public-read', 'catalog-item-owner-reference', 'catalog-list-anonymous-reference']
  for (const id of ids) {
    const result = results.find(r => r.id === id)
    assert.ok(result, `${id} must be in the Tier-0 corpus`)
    assert.equal(result.dismissed, true, result.reason)
    assert.match(result.reason, /public|identical|reference/i)
  }
})

test('tier0: every corpus archetype stays dismissed (no regression in the shared invariants)', () => {
  const { results } = runCorpus(CORPUS)
  for (const result of results) assert.equal(result.dismissed, true, `${result.id}: ${result.reason}`)
})

test('tier0: each of the three over-claimed catalog routes is covered by an archetype', () => {
  const corpus = loadCorpus(CORPUS)
  const routes = ['/api/v1/catalog', '/api/v1/catalog/:productId', '/api/v1/stores/:storeId/catalog/:productId']
  const family = corpus.filter(a => a.id.startsWith('catalog-'))
  for (const route of routes) {
    assert.ok(
      family.some(a => a.input.steps.some(s => s.route === route)),
      `${route} must be replayed by a catalog archetype`,
    )
  }
})

// ---------------------------------------------------------------------------
// 2. The dismissal rule itself: publicness vs a genuine private crossing
// ---------------------------------------------------------------------------

test('publicness: anonymous store-page body equal to the owner reference is dismissed', () => {
  const ownerBody = {
    store: STORE_A, viewer: STORE_A,
    product: { id: '204', title: 'Item 1', price: 1200 },
    memberNote: 'loyalty rbc_9ca676_0123456789ab',
  }
  const assessment = assessAuthorizationImpact({
    impactClass: 'authorization',
    steps: [
      step({ id: 'ctl_none', arm: 'control', method: 'GET', status: 200, actor: anon, route: '/api/v1/stores/:storeId/catalog/:productId', json: { store: '000000', viewer: '000000', product: null, memberNote: '' } }),
      step({ id: 'owner_ref', arm: 'control', method: 'GET', status: 200, actor: ownerA, route: '/api/v1/stores/:storeId/catalog/:productId', json: ownerBody }),
      step({ id: 'probe_anon', arm: 'probe', method: 'GET', status: 200, actor: anon, route: '/api/v1/stores/:storeId/catalog/:productId', json: ownerBody }),
    ],
  })
  assert.equal(assessment.satisfied, false, assessment.reason)
  assert.match(assessment.reason, /publicness/i)
})

test('publicness: a non-owner catalog item read identical to the owner reference is dismissed', () => {
  const item = { id: 201, external_id: '201', store_id: STORE_A, title: 'Item 2', price: 1700, stock: 5, body_html: '<p>Quality item 2</p>' }
  const assessment = assessAuthorizationImpact({
    impactClass: 'authorization',
    steps: [
      step({ id: 'owner_ref', arm: 'control', method: 'GET', status: 200, actor: ownerA, route: '/api/v1/catalog/:productId', json: item }),
      step({ id: 'ctl_list', arm: 'control', method: 'GET', status: 200, actor: ownerB, route: '/api/v1/catalog', json: { products: [{ external_id: '205', title: 'Item 1', price: 1200, stock: 5 }] } }),
      step({ id: 'probe_foreign', arm: 'probe', method: 'GET', status: 200, actor: ownerB, route: '/api/v1/catalog/:productId', json: item }),
    ],
  })
  assert.equal(assessment.satisfied, false, assessment.reason)
  assert.match(assessment.reason, /publicness/i)
})

test('publicness: an anonymous listing identical to the owner reference is dismissed', () => {
  const listing = { products: [{ external_id: '201', title: 'Item 1', price: 1200, stock: 5 }] }
  const assessment = assessAuthorizationImpact({
    impactClass: 'authorization',
    steps: [
      step({ id: 'owner_ref', arm: 'control', method: 'GET', status: 200, actor: ownerA, json: listing }),
      step({ id: 'probe_anon', arm: 'probe', method: 'GET', status: 200, actor: anon, json: listing }),
    ],
  })
  assert.equal(assessment.satisfied, false, assessment.reason)
  assert.match(assessment.reason, /publicness/i)
})

test('publicness: differences confined to public listing fields are still dismissed', () => {
  const assessment = assessAuthorizationImpact({
    impactClass: 'authorization',
    steps: [
      step({ id: 'owner_ref', arm: 'control', method: 'GET', status: 200, actor: ownerA, route: '/api/v1/catalog/:productId', json: { external_id: '201', title: 'Item 2', price: 1700, stock: 5 } }),
      step({ id: 'ctl_list', arm: 'control', method: 'GET', status: 200, actor: ownerB, route: '/api/v1/catalog', json: { products: [{ external_id: '205', title: 'Item 1', price: 1200, stock: 5 }] } }),
      step({ id: 'probe_foreign', arm: 'probe', method: 'GET', status: 200, actor: ownerB, route: '/api/v1/catalog/:productId', json: { external_id: '201', title: 'Item 2', price: 1700, stock: 4 } }),
    ],
  })
  assert.equal(assessment.satisfied, false, assessment.reason)
  assert.match(assessment.reason, /fields the public listing already exposes|publicness/i)
})

test('genuine private catalog read with a differing tenant canary still confirms', () => {
  const assessment = assessAuthorizationImpact({
    impactClass: 'authorization',
    steps: [
      step({ id: 'owner_ref', arm: 'control', method: 'GET', status: 200, actor: ownerA, route: '/api/v1/catalog/:productId', json: { external_id: '201', store_id: STORE_A, privateNote: 'rbc_9ca676_0123456789ab' } }),
      step({ id: 'probe_foreign', arm: 'probe', method: 'GET', status: 200, actor: ownerB, route: '/api/v1/catalog/:productId', json: { external_id: '202', store_id: STORE_B, privateNote: 'rbc_6ea2e7_0123456789ab' } }),
    ],
  })
  assert.equal(assessment.satisfied, true, assessment.reason)
  assert.match(assessment.reason, /Cross-tenant read/)
})

test('genuine cross-tenant order read (same body, customer note) still confirms', () => {
  const body = { id: '101', status: 'confirmed', total: 3400, customer: { name: 'Dana', email: `dana@${STORE_A}.test`, note: 'loyalty rbc_9ca676_0123456789ab' } }
  const assessment = assessAuthorizationImpact({
    impactClass: 'authorization',
    steps: [
      step({ id: 'c2', arm: 'control', method: 'GET', status: 404, actor: ownerA, route: '/api/v1/purchases/:orderId' }),
      step({ id: 'c1', arm: 'control', method: 'GET', status: 200, actor: ownerA, route: '/api/v1/purchases/:orderId', json: body }),
      step({ id: 'p1', arm: 'probe', method: 'GET', status: 200, actor: ownerB, route: '/api/v1/purchases/:orderId', json: body }),
    ],
  })
  assert.equal(assessment.satisfied, true, assessment.reason)
})

test('publicness: an owner-scoped identity bound to the reference defeats dismissal', () => {
  const assessment = assessAuthorizationImpact({
    impactClass: 'authorization',
    steps: [
      step({ id: 'owner_ref', arm: 'control', method: 'GET', status: 200, actor: ownerA, route: '/api/v1/catalog/:productId', json: { external_id: '201', owner_id: 'persona_a' } }),
      step({ id: 'probe_foreign', arm: 'probe', method: 'GET', status: 200, actor: ownerB, route: '/api/v1/catalog/:productId', json: { external_id: '201', owner_id: 'persona_a' } }),
    ],
  })
  assert.equal(assessment.satisfied, true, assessment.reason)
})

// ---------------------------------------------------------------------------
// 3. Fixture: public storefront payloads carry no tenant canary, cache-poison does
// ---------------------------------------------------------------------------

interface PageBody { store: string; viewer: string; product: unknown; memberNote: string }

function harness(salt: string) {
  const canaries = createCanaryRegistry(salt)
  const noteA = canaries.tenantToken(STORE_A, 'customer')
  const noteB = canaries.tenantToken(STORE_B, 'customer')
  const storeNames: Record<string, string> = { [STORE_A]: 'Aurora Goods', [STORE_B]: 'Borealis Supply' }
  const handlers = new Map<string, (ctx: unknown) => unknown>()
  const app = {
    db: {
      get(sql: string, params: readonly unknown[]) {
        if (/FROM stores/.test(sql)) return { name: storeNames[String(params[0])] ?? null }
        if (/FROM customers/.test(sql)) {
          const slug = String(params[0])
          if (slug === STORE_A) return { note: `loyalty ${noteA}` }
          if (slug === STORE_B) return { note: `loyalty ${noteB}` }
        }
        return undefined
      },
    },
    findByExternalId: (table: string, id: string) => (table === 'products' && id === '204'
      ? { external_id: '204', title: 'Item 1', price: 1200 }
      : undefined),
    paramName: (name: string) => name,
    route(key: string, handler: (ctx: unknown) => unknown) {
      handlers.set(key, handler)
      return app
    },
  } as unknown as AppContext
  registerStorePage(app)
  const page = (actor: { tenant: string | null; headers?: Record<string, string> }): PageBody => {
    const handler = handlers.get('storeProductPage')!
    return handler({
      params: { storeId: STORE_A, productId: '204' },
      headers: actor.headers ?? {},
      tenant: actor.tenant,
      json: (body: unknown) => body,
    }) as PageBody
  }
  return { page, canaries, noteA, noteB }
}

const CANARY_SHAPE = /rb[cs]_[a-z0-9]+_[0-9a-f]{12}/

test('fixture: an anonymous storefront page ships no tenant canary (publicness)', () => {
  const { page } = harness('catalog-public-fixture')
  const body = page({ tenant: null })
  assert.equal(CANARY_SHAPE.test(JSON.stringify(body)), false, JSON.stringify(body))
  assert.equal(body.memberNote, 'Welcome to Aurora Goods')
  assert.deepEqual(body.product, { id: '204', title: 'Item 1', price: 1200 })
})

test('fixture: a non-owner authenticated caller never receives another store canary', () => {
  const { page } = harness('catalog-public-fixture')
  const body = page({ tenant: STORE_B })
  // The caller may see their OWN loyalty note (their data, on a page they can read), never store A's.
  assert.doesNotMatch(JSON.stringify(body), /rbc_9ca676/, JSON.stringify(body))
  assert.match(body.memberNote, /^loyalty rbc_6ea2e7_/)
  // A forged x-store header does not unlock the other store's customer note.
  const forged = page({ tenant: STORE_B, headers: { 'x-store': STORE_A } })
  assert.equal(CANARY_SHAPE.test(JSON.stringify(forged)), false, JSON.stringify(forged))
  assert.equal(forged.memberNote, 'Welcome to Aurora Goods')
})

test('fixture: the authenticated owner page still personalizes, so cache poisoning stays detectable', () => {
  const { page, canaries, noteA } = harness('catalog-public-fixture')
  const warm = page({ tenant: STORE_A })
  assert.match(JSON.stringify(warm), new RegExp(noteA), 'the owner page carries its own loyalty note')
  const events: Array<{ kind: string; detail: Record<string, unknown> }> = []
  const oracle = { emit: (kind: string, detail: Record<string, unknown>) => events.push({ kind, detail }) } as unknown as Oracle
  const cache = createResponseCache()
  const key = cache.keyFor('storeProductPage', '/api/v1/stores/:storeId/catalog/:productId', {}, {}, { ttlMs: 30_000 })
  cache.set(key, { status: 200, body: JSON.stringify(warm), contentType: 'application/json', tenant: STORE_A, actor: 'persona_a', expiresAt: Date.now() + 30_000 })
  const hit = cache.get(key)!
  detectCachePoison(oracle, canaries, hit, key, 'persona_b', STORE_B)
  assert.equal(events.filter(e => e.kind === 'cache_poisoned').length, 1, 'a cross-tenant cache HIT still proves the planted target')
})

test('fixture: customer personalization is behind the signed-in store guard', () => {
  const source = readFileSync(join(repoRoot, 'benchmarks/realistic-bench/apps/shopflow/sites/storefront-cache-poison/vulnerable.ts'), 'utf8')
  assert.match(source, /ctx\.tenant !== null && ctx\.tenant === viewer/)
  assert.ok(source.indexOf('ctx.tenant === viewer') < source.indexOf('FROM customers'))
  assert.match(source, /member \? String\(member\.note\) : shop \? `Welcome to/)
})
