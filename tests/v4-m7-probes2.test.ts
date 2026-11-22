/**
 * M7 held-out2 probe formation: bounded, semantics-driven hypotheses.
 *
 * Guards the blast-radius gates added for the parallel climb: placeholder server actions are not
 * invoked, races are limited to consumption-shaped endpoints, and identifier recognition stays
 * structural (ids only, no route-word false positives).
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import { formHypotheses, looksLikeIdSegment, profileCaps } from '../scripts/benchmark-probes.ts'
import type { DiscoveredEndpoint } from '../scripts/benchmark-probes.ts'

const caps = profileCaps('v4-full')

function ep(over: Partial<DiscoveredEndpoint> & Pick<DiscoveredEndpoint, 'method' | 'path'>): DiscoveredEndpoint {
  return { params: [], source: 'openapi', ...over }
}

describe('M7 held-out2: server-action hypotheses', () => {
  test('invokes concrete actions but skips framework placeholder ids', () => {
    const endpoints: DiscoveredEndpoint[] = [
      ep({ method: 'POST', path: '/_actions/updateOrgPlan' }),
      ep({ method: 'POST', path: '/_next/action/:id' }),
    ]
    const plan = formHypotheses(endpoints, caps)
    const actions = plan.hypotheses.filter(h => h.probeClass === 'authz_matrix')
    assert.equal(actions.length, 1)
    assert.equal(actions[0].endpoint.path, '/_actions/updateOrgPlan')
    assert.equal(actions[0].serverAction, true)
  })
})

describe('M7 held-out2: race hypothesis scope', () => {
  test('races single-use consumption endpoints only', () => {
    const endpoints: DiscoveredEndpoint[] = [
      ep({
        method: 'POST', path: '/api/v1/credits/redeem',
        params: [{ name: 'code', location: 'json', isObjectId: false, isCsrf: false }],
      }),
      ep({
        method: 'POST', path: '/api/v1/credits/vouchers',
        params: [],
      }),
      ep({
        method: 'POST', path: '/api/v1/account/password/reset',
        params: [{ name: 'token', location: 'json', isObjectId: false, isCsrf: false }],
      }),
    ]
    const plan = formHypotheses(endpoints, caps)
    const races = plan.hypotheses.filter(h => h.probeClass === 'race_burst')
    assert.equal(races.length, 1)
    assert.equal(races[0].endpoint.path, '/api/v1/credits/redeem')
    assert.equal(races[0].raceProducerPath, '/api/v1/credits/vouchers')
  })
})

describe('M7 held-out2: identifier shape', () => {
  test('accepts prefixed/numeric ids and rejects route words', () => {
    for (const id of ['p_acme_1', 'u-1001', '1001', '0f8fad5b-d9cb-469f-a165-70867728950e', 'ord_1234']) {
      assert.equal(looksLikeIdSegment(id), true, id)
    }
    for (const word of ['projects', 'activity', 'api', 'v1', 'profile', 'openid-configuration', 'well-known']) {
      assert.equal(looksLikeIdSegment(word), false, word)
    }
  })
})
