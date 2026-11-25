import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { assessAuthorizationImpact, isObjectScopedRequest } from '../src/server/oracle-invariants.ts'

describe('collection BOLA/BFLA precision vs object-scoped GraphQL reads', () => {
  test('isObjectScopedRequest recognizes object-scoped GraphQL args and variables, rejects bare collections', () => {
    assert.equal(isObjectScopedRequest({
      method: 'POST',
      route: '/graphql',
      pathAndQuery: '/graphql',
      requestJson: { query: 'query { user(id: "u_1") { invoices { id memo } } }' },
    }), true)

    assert.equal(isObjectScopedRequest({
      method: 'POST',
      route: '/graphql',
      pathAndQuery: '/graphql',
      requestJson: {
        query: 'query($target: ID!) { user(id: $target) { invoices { id memo } } }',
        variables: { target: 'u_1' },
      },
    }), true)

    // Unparameterized / pagination-only GraphQL collection reads stay unscoped (fail closed).
    assert.equal(isObjectScopedRequest({
      method: 'POST',
      route: '/graphql',
      pathAndQuery: '/graphql',
      requestJson: { query: 'query { invoices(limit: 10) { id amount } }' },
    }), false)

    // Unbound variable with missing value stays unscoped.
    assert.equal(isObjectScopedRequest({
      method: 'POST',
      route: '/graphql',
      pathAndQuery: '/graphql',
      requestJson: { query: 'query($target: ID!) { user(id: $target) { id } }', variables: {} },
    }), false)

    // Bare REST collection GET stays unscoped.
    assert.equal(isObjectScopedRequest({
      method: 'GET',
      route: '/api/v1/charges',
      pathAndQuery: '/api/v1/charges',
    }), false)
  })

  test('assessAuthorizationImpact accepts object-scoped GraphQL nested BOLA and fails closed on bare GraphQL collection', () => {
    const objectScoped = assessAuthorizationImpact({
      impactClass: 'authorization',
      steps: [
        {
          id: 'c1',
          arm: 'control',
          method: 'POST',
          route: '/graphql',
          pathAndQuery: '/graphql',
          status: 200,
          actor: { handle: 'persona_a', role: 'member', tenant: null, auth: 'bearer', sameSite: null },
          requestJson: { query: 'query { user(id: "u_1") { email invoices { id amount } } }' },
          json: { data: { user: { id: 'u_1', email: 'alice@tenant-a.example', invoices: [{ id: 'inv_1', amount: 4900 }] } } },
        },
        {
          id: 'p1',
          arm: 'probe',
          method: 'POST',
          route: '/graphql',
          pathAndQuery: '/graphql',
          status: 200,
          actor: { handle: 'persona_b', role: 'member', tenant: null, auth: 'bearer', sameSite: null },
          requestJson: { query: 'query { user(id: "u_1") { email invoices { id amount } } }' },
          json: { data: { user: { id: 'u_1', email: 'alice@tenant-a.example', invoices: [{ id: 'inv_1', amount: 4900 }] } } },
        },
      ],
    })
    assert.equal(objectScoped.satisfied, true, objectScoped.reason)

    const bareCollection = assessAuthorizationImpact({
      impactClass: 'authorization',
      steps: [
        {
          id: 'c1',
          arm: 'control',
          method: 'POST',
          route: '/graphql',
          pathAndQuery: '/graphql',
          status: 403,
          actor: { handle: 'owner_a', role: 'owner', tenant: 'tenant-a', auth: 'bearer', sameSite: null },
          requestJson: { query: 'query { charges { id amount } }' },
          json: { errors: [{ message: 'forbidden' }] },
        },
        {
          id: 'p1',
          arm: 'probe',
          method: 'POST',
          route: '/graphql',
          pathAndQuery: '/graphql',
          status: 200,
          actor: { handle: 'viewer_a', role: 'viewer', tenant: 'tenant-a', auth: 'bearer', sameSite: null },
          requestJson: { query: 'query { charges { id amount } }' },
          json: { data: { charges: [{ id: 'chg_1', amount: 1999 }] } },
        },
      ],
    })
    assert.equal(bareCollection.satisfied, false)
    assert.match(bareCollection.reason, /Bare collection GET/i)
  })
})
