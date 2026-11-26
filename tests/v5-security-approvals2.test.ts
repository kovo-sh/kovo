import assert from 'node:assert/strict'
import test from 'node:test'
import {
  authorizeStateChange,
  evaluateTier3Approval,
  matchesApprovedEndpointPattern,
  MAX_KEYWORD_SCAN_CHARS,
  normalizeApprovalPathPattern,
} from '../src/server/approval-judge.ts'
import type { StateChangeApprovalContext } from '../src/server/approval-judge.ts'
import { BrokerApprovalRequired, BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant, Transport } from '../src/server/broker.ts'

// ============================================================================
// Security wave 2 — closes re-audit HIGH #1 (residual approval bypasses)
//
// A. 307/308 redirects re-send an approved state change to a different path without a fresh
//    exact-fingerprint authorization (and the exchange only recorded the original path).
// B. The idempotent-POST path-substring gate skipped the whole Tier-3 approval pipeline.
// C. Operator patterns over-matched (wildcards covered sibling verbs / arbitrary depth) and were
//    evaluated before hard escalations, including context-less RCE replays.
// D. Fast-path parity: duplicate top-level JSON keys, compressed bodies, and over-cap bodies.
// ============================================================================

const PUBLIC_ORIGIN = 'https://app.example.com'
const PUBLIC_ADDRESS = '93.184.216.34'

type WireRequest = { method: string; path: string; body?: string }

function makeBroker(transport: Transport): RequestBroker {
  return new RequestBroker({
    resolve: async () => [{ address: PUBLIC_ADDRESS, family: 4 }],
    transport,
  })
}

function makeGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    origin: PUBLIC_ORIGIN,
    tier: 3,
    maxRpsPerOrigin: 100,
    allowLocalLab: false,
    canRead: () => true,
    audit: () => {},
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// A. 307/308 redirects must not carry an approval to another path
// ---------------------------------------------------------------------------

test('A: an approved POST followed by a 307 is refused at the redirect target without a second approval', async () => {
  const wire: WireRequest[] = []
  const hookPaths: string[] = []
  const broker = makeBroker(async (url, _address, _signal, options) => {
    wire.push({ method: options?.method ?? 'GET', path: `${url.pathname}${url.search}`, body: options?.body })
    if (url.pathname === '/safe-update') {
      return { status: 307, headers: { location: '/dangerous-delete' }, body: '' }
    }
    return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }
  })
  const grant = makeGrant({
    isStateChangeApproved: (_origin, _method, pathAndQuery) => {
      hookPaths.push(pathAndQuery)
      return pathAndQuery === '/safe-update'
    },
  })

  await assert.rejects(
    broker.executeHttp({
      origin: PUBLIC_ORIGIN,
      method: 'POST',
      pathAndQuery: '/safe-update',
      headers: { 'Content-Type': 'application/json' },
      body: '{"action":"update","value":1}',
    }, grant, AbortSignal.timeout(5_000)),
    err => err instanceof BrokerApprovalRequired && err.pathAndQuery === '/dangerous-delete',
    'the redirect target must re-escalate with its own path in the error',
  )

  assert.deepEqual(wire.map(r => `${r.method} ${r.path}`), ['POST /safe-update'],
    'no bytes may be sent to the unapproved redirect target')
  assert.deepEqual(hookPaths, ['/safe-update', '/dangerous-delete'],
    'the approval hook must be consulted for the redirect target')
})

test('A: a second exact approval for the redirect target lets the 307 proceed and records the redirected path', async () => {
  const wire: WireRequest[] = []
  const broker = makeBroker(async (url, _address, _signal, options) => {
    wire.push({ method: options?.method ?? 'GET', path: `${url.pathname}${url.search}`, body: options?.body })
    if (url.pathname === '/safe-update') {
      return { status: 307, headers: { location: '/dangerous-delete?mode=apply' }, body: '' }
    }
    return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }
  })
  const approved = new Set(['/safe-update', '/dangerous-delete?mode=apply'])
  const seenContexts: StateChangeApprovalContext[] = []
  const grant = makeGrant({
    isStateChangeApproved: (_origin, _method, pathAndQuery, context) => {
      if (context) seenContexts.push(context)
      return approved.has(pathAndQuery)
    },
  })

  const res = await broker.executeHttp({
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/safe-update',
    headers: { 'Content-Type': 'application/json' },
    body: '{"action":"update","value":1}',
  }, grant, AbortSignal.timeout(5_000))

  assert.deepEqual(wire.map(r => `${r.method} ${r.path}`), [
    'POST /safe-update',
    'POST /dangerous-delete?mode=apply',
  ], 'the same method and body are re-sent only after the target approval')
  assert.equal(wire[1]?.body, '{"action":"update","value":1}')
  assert.equal(res.finalOrigin, PUBLIC_ORIGIN)
  assert.equal(res.pathAndQuery, '/safe-update', 'the original requested path stays visible')
  assert.equal(res.finalPathAndQuery, '/dangerous-delete?mode=apply', 'the exchange records the redirected path')
  assert.deepEqual(res.redirectPaths, ['/dangerous-delete?mode=apply'])
  assert.ok(seenContexts.length >= 2, 'both the original and the redirect target carry exact request context')
})

test('A: GET redirects still follow without an approval and record the redirected path', async () => {
  const wire: WireRequest[] = []
  let hookCalls = 0
  const broker = makeBroker(async (url, _address, _signal, options) => {
    wire.push({ method: options?.method ?? 'GET', path: `${url.pathname}${url.search}` })
    if (url.pathname === '/start') {
      return { status: 302, headers: { location: '/landing?from=start' }, body: '' }
    }
    return { status: 200, headers: { 'content-type': 'text/html' }, body: 'ok' }
  })
  const grant = makeGrant({
    isStateChangeApproved: () => {
      hookCalls += 1
      return false
    },
  })

  const res = await broker.executeHttp({
    origin: PUBLIC_ORIGIN,
    method: 'GET',
    pathAndQuery: '/start',
  }, grant, AbortSignal.timeout(5_000))

  assert.deepEqual(wire.map(r => `${r.method} ${r.path}`), ['GET /start', 'GET /landing?from=start'])
  assert.equal(hookCalls, 0, 'read-only redirects never need a state-change approval')
  assert.equal(res.finalPathAndQuery, '/landing?from=start')
  assert.deepEqual(res.redirectPaths, ['/landing?from=start'])
})

// ---------------------------------------------------------------------------
// B. No path-substring fast path may skip Tier-3 authorization
// ---------------------------------------------------------------------------

test('B: every non-GET goes through the approval hook, even on search/query-shaped paths', async () => {
  const broker = makeBroker(async () => ({
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: '{"ok":true}',
  }))
  const stateChangingBody = '{"action":"update","target":"profile"}'
  const cases: Array<{ method: 'POST' | 'PUT' | 'PATCH' | 'DELETE'; pathAndQuery: string }> = [
    { method: 'POST', pathAndQuery: '/api/query' },
    { method: 'POST', pathAndQuery: '/api/search?scope=all' },
    { method: 'POST', pathAndQuery: '/graphql' },
    { method: 'PUT', pathAndQuery: '/api/query' },
    { method: 'PATCH', pathAndQuery: '/api/search' },
    { method: 'DELETE', pathAndQuery: '/api/query' },
  ]

  for (const c of cases) {
    let hookCalls = 0
    const grant = makeGrant({
      // The legacy predicate must never authorize anything by itself.
      isIdempotentPostAllowed: () => true,
      isStateChangeApproved: () => {
        hookCalls += 1
        return false
      },
    })
    await assert.rejects(
      broker.executeHttp({
        origin: PUBLIC_ORIGIN,
        method: c.method,
        pathAndQuery: c.pathAndQuery,
        headers: { 'Content-Type': 'application/json' },
        body: stateChangingBody,
      }, grant, AbortSignal.timeout(5_000)),
      BrokerApprovalRequired,
      `${c.method} ${c.pathAndQuery} must require approval`,
    )
    assert.equal(hookCalls, 1, `${c.method} ${c.pathAndQuery} must consult the approval hook exactly once`)
  }
})

test('B: a path-substring idempotent predicate cannot authorize a Tier-2 state change', async () => {
  const wire: WireRequest[] = []
  const broker = makeBroker(async (url, _address, _signal, options) => {
    wire.push({ method: options?.method ?? 'GET', path: url.pathname })
    return { status: 200, headers: { 'content-type': 'application/json' }, body: '{}' }
  })
  const grant = makeGrant({
    tier: 2,
    isIdempotentPostAllowed: () => true,
  })

  await assert.rejects(
    broker.executeHttp({
      origin: PUBLIC_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/query',
      headers: { 'Content-Type': 'application/json' },
      body: '{"action":"update"}',
    }, grant, AbortSignal.timeout(5_000)),
    BrokerDenied,
  )
  assert.equal(wire.length, 0, 'no state-changing request may leave the broker on the legacy predicate')
})

test('B: when the approval hook authorizes the exact request, it proceeds', async () => {
  const wire: WireRequest[] = []
  const broker = makeBroker(async (url, _address, _signal, options) => {
    wire.push({ method: options?.method ?? 'GET', path: url.pathname })
    return { status: 200, headers: { 'content-type': 'application/json' }, body: '{}' }
  })
  let hookCalls = 0
  const grant = makeGrant({
    isStateChangeApproved: (_origin, _method, pathAndQuery, context) => {
      hookCalls += 1
      return pathAndQuery === '/api/query' && context?.body === '{"action":"update"}'
    },
  })

  const res = await broker.executeHttp({
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/query',
    headers: { 'Content-Type': 'application/json' },
    body: '{"action":"update"}',
  }, grant, AbortSignal.timeout(5_000))
  assert.equal(res.status, 200)
  assert.equal(hookCalls, 1)
  assert.deepEqual(wire.map(r => `${r.method} ${r.path}`), ['POST /api/query'])
})

// ---------------------------------------------------------------------------
// C. Operator patterns: segment-aware, fixed depth, never before hard escalation
// ---------------------------------------------------------------------------

test('C: a pattern derived from an item-ID path does not cover a sibling verb or a deeper path', () => {
  const pathPattern = normalizeApprovalPathPattern('/api/items/123')
  assert.equal(pathPattern, '/api/items/*')
  const patterns = [{ origin: PUBLIC_ORIGIN, method: 'POST', pathPattern }]

  const match = (pathAndQuery: string) =>
    matchesApprovedEndpointPattern({ origin: PUBLIC_ORIGIN, method: 'POST', pathAndQuery }, patterns)

  assert.ok(match('/api/items/123'), 'the exact ID-shaped target still matches')
  assert.ok(match('/api/items/456'), 'a different ID-shaped target matches')
  assert.equal(match('/api/items/delete'), undefined, 'a wildcard must not cover a sibling destructive verb')
  assert.equal(match('/api/items/123/settings'), undefined, 'fixed segment count: no arbitrary-depth match')
  assert.equal(match('/api/items/123/456'), undefined, 'fixed segment count: no arbitrary-depth match')
})

test('C: exact literal segments still match, and a prefix match requires an explicit operator `**`', () => {
  const exact = [{ origin: PUBLIC_ORIGIN, method: 'POST', pathPattern: '/api/items/update' }]
  assert.ok(matchesApprovedEndpointPattern({ origin: PUBLIC_ORIGIN, method: 'POST', pathAndQuery: '/api/items/update' }, exact))
  assert.equal(matchesApprovedEndpointPattern({ origin: PUBLIC_ORIGIN, method: 'POST', pathAndQuery: '/api/items/update/9' }, exact), undefined)
  assert.equal(matchesApprovedEndpointPattern({ origin: PUBLIC_ORIGIN, method: 'POST', pathAndQuery: '/api/items/delete' }, exact), undefined)

  const prefix = [{ origin: PUBLIC_ORIGIN, method: 'POST', pathPattern: '/api/items/**', source: 'operator_explicit' as const }]
  assert.ok(matchesApprovedEndpointPattern({ origin: PUBLIC_ORIGIN, method: 'POST', pathAndQuery: '/api/items/123/settings' }, prefix),
    'an explicit `**` prefix is the only arbitrary-depth form')
  assert.equal(matchesApprovedEndpointPattern({ origin: PUBLIC_ORIGIN, method: 'POST', pathAndQuery: '/other/items/123' }, prefix), undefined)
})

test('C: hard-escalated requests still escalate even with a matching pattern', async () => {
  const patterns = [{ origin: PUBLIC_ORIGIN, method: 'POST', pathPattern: '/api/items/*' }]
  const decide = (overrides: Record<string, unknown>) => evaluateTier3Approval({
    policy: 'auto_review',
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/123',
    approvedPatterns: patterns,
    leaseAuthorizes: () => true,
    offline: true,
    ...overrides,
  })

  // v6: English keyword payloads are no longer an escalation trigger. The explicit operator
  // pattern owns this route, so the same request is now authorized by the pattern — safety comes
  // from the environment contract + durable route lease, not from guessing at the body words.
  const destructiveBody = await decide({ bodyPreview: '{"operation":"refund","amount":1}' })
  assert.equal(destructiveBody.decision, 'approve')
  assert.equal(destructiveBody.stage, 'approved_pattern')

  // Operator pattern ("Approve similar") honors well-formed multipart & DELETE on that exact route,
  // while non-overridable structural risks (malformed multipart, compressed body, rce_proof) and
  // race bursts never match a pattern.
  const multipartWithPattern = await decide({ hasMultipart: true })
  assert.equal(multipartWithPattern.decision, 'approve')
  assert.equal(multipartWithPattern.stage, 'approved_pattern')

  const malformedMultipart = await decide({ headers: { 'content-type': 'multipart/form-data' } })
  assert.equal(malformedMultipart.decision, 'escalate_human')
  assert.equal(malformedMultipart.stage, 'hard_escalation')

  const race = await decide({ isRaceBurst: true })
  assert.equal(race.decision, 'escalate_human')
  assert.notEqual(race.stage, 'approved_pattern', 'patterns never pre-approve race bursts')

  const approvedDelete = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: PUBLIC_ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/items/123',
    approvedPatterns: [{ origin: PUBLIC_ORIGIN, method: 'DELETE', pathPattern: '/api/items/*' }],
    leaseAuthorizes: () => true,
    offline: true,
  })
  assert.equal(approvedDelete.decision, 'approve')
  assert.equal(approvedDelete.stage, 'approved_pattern')

  const unapprovedDelete = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: PUBLIC_ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/other/123',
    approvedPatterns: [{ origin: PUBLIC_ORIGIN, method: 'DELETE', pathPattern: '/api/items/*' }],
    offline: true,
  })
  assert.equal(unapprovedDelete.decision, 'escalate_human')
  assert.equal(unapprovedDelete.stage, 'hard_escalation')

  // A non-escalated ID target still matches the pattern after the ordering change.
  const benign = await decide({})
  assert.equal(benign.stage, 'approved_pattern')
})

test('C: patterns never authorize an RCE proof or malformed multipart, including when context is omitted', () => {
  const patterns = [{ origin: PUBLIC_ORIGIN, method: 'POST', pathPattern: '/api/items/*' }]

  const withoutContext = authorizeStateChange({
    runId: 'run-rce',
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/123',
    approvedPatterns: patterns,
  })
  assert.equal(withoutContext.approved, false, 'context-less calls must not inherit a pattern grant')

  const withRce = authorizeStateChange({
    runId: 'run-rce',
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/123',
    context: { personaHandle: null, isRceProof: true },
    approvedPatterns: patterns,
  })
  assert.equal(withRce.approved, false, 'rce_proof is never covered by an operator pattern')

  const withWellFormedMultipart = authorizeStateChange({
    runId: 'run-rce',
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/123',
    context: { personaHandle: null, hasMultipart: true },
    approvedPatterns: patterns,
    leaseAuthorizes: () => true,
  })
  assert.equal(withWellFormedMultipart.approved, true, 'explicit operator pattern authorizes well-formed multipart on that route')
  assert.equal(withWellFormedMultipart.via, 'operator_pattern')

  const withCompressed = authorizeStateChange({
    runId: 'run-rce',
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/123',
    context: { personaHandle: null, hasCompressedBody: true },
    approvedPatterns: patterns,
  })
  assert.equal(withCompressed.approved, false, 'compressed bodies are never covered by an operator pattern')
})

test('C: rce_proof without context is refused by the judge', async () => {
  const result = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/123',
    isRceProof: true,
    approvedPatterns: [{ origin: PUBLIC_ORIGIN, method: 'POST', pathPattern: '/api/items/*' }],
    offline: true,
  })
  assert.equal(result.decision, 'escalate_human')
  assert.equal(result.stage, 'hard_escalation')
})

// ---------------------------------------------------------------------------
// D. Fast-path parity: duplicate keys, compressed bodies, over-cap bodies
// ---------------------------------------------------------------------------

test('D: a duplicate top-level `query` key cannot take the GraphQL fast path', async () => {
  const duplicated = '{"query":"query Viewer { viewer { id } }","query":"mutation { deleteAccount }"}'
  const result = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/graphql',
    personaHandle: 'user_a',
    bodyPreview: duplicated,
    offline: true,
  })
  assert.notEqual(result.stage, 'benign_fast_path', 'duplicate keys must not be classified as a read-only query')
  assert.equal(result.decision, 'escalate_human')
})

test('D: a duplicate top-level key on a search-shaped path cannot take the benign fast path', async () => {
  const result = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/search',
    personaHandle: 'user_a',
    bodyPreview: '{"q":"term","q":"term","operation":"apply"}',
    offline: true,
  })
  assert.notEqual(result.stage, 'benign_fast_path')
  assert.equal(result.decision, 'escalate_human')
})

test('D: a compressed state-change body escalates instead of being auto-approved', async () => {
  const fromHeader = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/profile/update',
    personaHandle: 'user_a',
    headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' },
    bodyPreview: '\u001f\u008b\u0008\u0000compressed-bytes',
    offline: true,
  })
  assert.equal(fromHeader.decision, 'escalate_human')
  assert.equal(fromHeader.stage, 'hard_escalation')

  const fromFlag = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/search',
    personaHandle: 'user_a',
    bodyPreview: 'compressed-bytes',
    hasCompressedBody: true,
    offline: true,
  })
  assert.equal(fromFlag.decision, 'escalate_human')
  assert.equal(fromFlag.stage, 'hard_escalation')

  // Patterns must not launder a compressed body either.
  const pattern = authorizeStateChange({
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/123',
    context: { personaHandle: null, body: 'compressed-bytes', hasCompressedBody: true },
    approvedPatterns: [{ origin: PUBLIC_ORIGIN, method: 'POST', pathPattern: '/api/items/*' }],
  })
  assert.equal(pattern.approved, false)
})

test('D: a body over the classification cap escalates instead of being auto-approved', async () => {
  const oversized = JSON.stringify({ pad: 'a'.repeat(MAX_KEYWORD_SCAN_CHARS + 1) })
  assert.ok(oversized.length > MAX_KEYWORD_SCAN_CHARS)

  const result = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: PUBLIC_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/search',
    personaHandle: 'user_a',
    bodyPreview: oversized,
    offline: true,
  })
  assert.equal(result.decision, 'escalate_human')
  assert.equal(result.stage, 'hard_escalation')
  assert.match(result.reason, /classification cap/i)
})
