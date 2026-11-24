/**
 * v7 SQLi quota stream: two general selection defects that masked accessible SQL injection targets.
 *
 * 1. Route-noun hint matching was a substring match, so `catalog` was treated as a search surface
 *    and its derived routes formed search-parameter SQLi hypotheses that consumed the class quota.
 *    The predicate now matches whole path segments / whole tokens only.
 * 2. Class quotas are a flat cap: a genuine reading parameter verified by a paired differential
 *    (the engine's `activeQueryParams`, recon's `inferred_*:sensitive`) can rank just outside the
 *    SQLi quota and never be probed. Selection now reserves exactly one slot per class for such a
 *    candidate, and releases it to the normal ranking when no candidate needs it.
 *
 * Nothing here relaxes a probe or an oracle: a reserved candidate still runs the normal
 * differential and the normal replay/recipe confirmation path.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { enumerateHypotheses, pathHasSearchHint } from '../src/server/deterministic-engine.ts'
import type {
  EndpointHarvest,
  EngineEndpoint,
  QuotaReservationEvent,
} from '../src/server/deterministic-engine.ts'

const BASE = 'http://127.0.0.1:4200'

function endpoint(
  overrides: Partial<EngineEndpoint> & Pick<EngineEndpoint, 'id' | 'method' | 'pathTemplate'>,
): EngineEndpoint {
  return {
    origin: BASE,
    params: [],
    riskScore: 40,
    ...overrides,
  }
}

function harvest(activeQueryParams: string[]): EndpointHarvest {
  return {
    ownerIds: [],
    otherIds: [],
    fields: [],
    values: {},
    otherValues: {},
    seedValues: [],
    activeQueryParams,
  }
}

/** Same quota inputs the product floor uses (`maxHypotheses=90`, `maxRequests=1800` => SQLi 17). */
const FLOOR_OPTIONS = { tier: 3, personas: [], maxHypotheses: 90, maxRequests: 1800 } as const

function select(
  endpoints: readonly EngineEndpoint[],
  harvests: ReadonlyMap<string, EndpointHarvest>,
): { keys: string[]; events: QuotaReservationEvent[] } {
  const events: QuotaReservationEvent[] = []
  const selected = enumerateHypotheses(endpoints, harvests, {
    ...FLOOR_OPTIONS,
    personas: [],
    onQuotaReservation: event => events.push(event),
  })
  return { keys: selected.map(hyp => hyp.key), events }
}

// ---------------------------------------------------------------------------------------------
// 1. Route-noun hint tokenisation
// ---------------------------------------------------------------------------------------------

test('search hint matches whole route tokens only, never a substring', () => {
  // Rule: a search hint is a whole path segment (or a whole token inside a segment, split on
  // `-`, `_`, `.`). `catalog` is a listing noun and must not match; `logs`/`audit-log` are
  // file/audit surfaces and belong to `pathHasFileHint`, not the search vocabulary.
  const expected: Array<[string, boolean]> = [
    ['/api/v1/search', true],
    ['/api/v1/searches', true],
    ['/api/v1/catalog-search', true],
    ['/api/v1/catalog/search', true],
    ['/api/v1/query', true],
    // Query-string keys are parameters, not route shape: `inferEndpointParams` already reads them,
    // so the hint predicate ignores the query string entirely.
    ['/api/v1/products?query=guardian', false],
    ['/api/v1/catalog', false],
    ['/api/v1/catalogs', false],
    ['/api/v1/catalog-items', false],
    ['/api/v1/catalog/:id', false],
    ['/api/v1/logs', false],
    ['/api/v1/audit-log', false],
    ['/api/v1/journal', false],
    ['/api/v1/reports', false],
  ]
  for (const [path, want] of expected) {
    assert.equal(pathHasSearchHint(path), want, `${path} search hint`)
  }
})

test('catalog routes no longer form search SQLi candidates; the search route still does', () => {
  const catalogs = Array.from({ length: 25 }, (_, idx) => endpoint({
    id: `ep-catalog-${idx}`,
    method: 'GET',
    pathTemplate: `/api/v1/catalog-${idx}`,
    riskScore: 150,
  }))
  const search = endpoint({
    id: 'ep-search',
    method: 'GET',
    pathTemplate: '/api/v1/search',
    params: [{ name: 'query', location: 'query' }],
    riskScore: 40,
  })
  const { keys } = select([...catalogs, search], new Map([['ep-search', harvest(['query'])]]))

  assert.equal(keys.some(key => key.startsWith('sqli_boolean|ep-catalog-')), false,
    'catalog listing routes must not generate SQLi hypotheses from a search-noun match')
  assert.ok(keys.includes('sqli_boolean|ep-search|query'),
    'the genuine search route keeps its SQLi hypothesis even behind 25 higher-risk routes')
})

// ---------------------------------------------------------------------------------------------
// 2. Evidence-based quota reservation
// ---------------------------------------------------------------------------------------------

test('verified reading param that would miss the SQLi quota gets one reserved slot', () => {
  // The search route forms two SQLi candidates (`query` verified, plus an unverified sibling name).
  // Sixteen higher-risk candidates fill the quota up to 17, so the verified candidate ranks 18th
  // and used to be dropped. Its `query` param is verified by the harvest differential
  // (`activeQueryParams`), which is the evidence the reservation is keyed on.
  const noise = Array.from({ length: 16 }, (_, idx) => endpoint({
    id: `ep-items-${idx}`,
    method: 'GET',
    pathTemplate: `/api/v1/items-${idx}`,
    params: [{ name: 'sku', location: 'query' }],
    riskScore: 150,
  }))
  const search = endpoint({
    id: 'ep-search',
    method: 'GET',
    pathTemplate: '/api/v1/search',
    params: [{ name: 'query', location: 'query' }],
    riskScore: 40,
  })
  const { keys, events } = select([...noise, search], new Map([['ep-search', harvest(['query'])]]))

  const searchKey = 'sqli_boolean|ep-search|query'
  assert.ok(keys.includes(searchKey), 'reserved candidate is selected despite ranking outside the quota')

  const event = events.find(entry => entry.class === 'sqli')
  assert.ok(event, 'sqli reservation decision is reported')
  assert.equal(event.released, false, 'the slot was used, not released')
  assert.equal(event.reservedFor, searchKey)
  assert.equal(event.quota, 17, 'product floor SQLi quota')
  assert.equal(event.rankBefore, 18, 'the candidate ranked just outside the quota')
  assert.equal(event.rankAfter, keys.indexOf(searchKey) + 1, 'reported position matches the plan')
})

test('reservation is released to the normal ranking when the verified candidate already fits', () => {
  // The verified search candidate ranks first, well inside the quota. No slot is held back, so the
  // selected set is exactly the normal quota fill (17 SQLi hypotheses here, never 18).
  const noise = Array.from({ length: 25 }, (_, idx) => endpoint({
    id: `ep-items-${idx}`,
    method: 'GET',
    pathTemplate: `/api/v1/items-${idx}`,
    params: [{ name: 'sku', location: 'query' }],
    riskScore: 100,
  }))
  const search = endpoint({
    id: 'ep-search',
    method: 'GET',
    pathTemplate: '/api/v1/search',
    params: [{ name: 'query', location: 'query' }],
    riskScore: 160,
  })
  const endpoints = [...noise, search]
  const evidence = new Map([['ep-search', harvest(['query'])]])
  const { keys, events } = select(endpoints, evidence)

  const searchKey = 'sqli_boolean|ep-search|query'
  const sqliKeys = keys.filter(key => key.startsWith('sqli_boolean|'))
  assert.equal(sqliKeys.length, 17, 'quota is unchanged when no reservation is needed')
  assert.ok(keys.includes(searchKey))

  const event = events.find(entry => entry.class === 'sqli')!
  assert.equal(event.released, true)
  assert.equal(event.reservedFor, searchKey)
  assert.ok(event.rankBefore <= event.quota, 'verified candidate was already inside the quota')
  assert.equal(event.rankAfter, keys.indexOf(searchKey) + 1)

  // Same quota fill without any verified-reading evidence: the slot went back to the normal
  // ranking instead of being wasted.
  const control = select(endpoints, new Map())
  assert.equal(control.keys.filter(key => key.startsWith('sqli_boolean|')).length, 17)
  assert.equal(control.events.length, 0, 'no reservation is evaluated without evidence')
})

test('reservation never fires for an unverified (merely inferred) parameter', () => {
  // Same surface, but the harvest did not prove the parameter is read. No evidence, no slot: the
  // candidate is dropped by the normal quota exactly as before.
  const noise = Array.from({ length: 17 }, (_, idx) => endpoint({
    id: `ep-items-${idx}`,
    method: 'GET',
    pathTemplate: `/api/v1/items-${idx}`,
    params: [{ name: 'sku', location: 'query' }],
    riskScore: 150,
  }))
  const search = endpoint({
    id: 'ep-search',
    method: 'GET',
    pathTemplate: '/api/v1/search',
    params: [{ name: 'query', location: 'query' }],
    riskScore: 40,
  })
  const { keys, events } = select([...noise, search], new Map([['ep-search', harvest([])]]))
  assert.equal(keys.includes('sqli_boolean|ep-search|query'), false)
  assert.equal(events.length, 0)
})

// ---------------------------------------------------------------------------------------------
// 3. Determinism
// ---------------------------------------------------------------------------------------------

test('quota reservation is deterministic under permuted surface and harvest order', () => {
  const noise = Array.from({ length: 20 }, (_, idx) => endpoint({
    id: `ep-items-${idx}`,
    method: 'GET',
    pathTemplate: `/api/v1/items-${idx}`,
    params: [{ name: 'sku', location: 'query' }],
    riskScore: 150,
  }))
  const search = endpoint({
    id: 'ep-search',
    method: 'GET',
    pathTemplate: '/api/v1/search',
    params: [{ name: 'query', location: 'query' }],
    riskScore: 40,
  })
  const first = select([...noise, search], new Map([['ep-search', harvest(['query'])]]))
  const second = select(
    [search, ...[...noise].reverse()],
    new Map([[ 'ep-search', harvest(['query']) ]]),
  )
  assert.deepEqual(second.keys, first.keys, 'identical surface => identical selection order')
  assert.deepEqual(second.events, first.events, 'identical reservation outcome')
})
