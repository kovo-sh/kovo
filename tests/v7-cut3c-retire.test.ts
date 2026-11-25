/**
 * Cut 3c-1 & floor-recipe wiring tests:
 *  (a) The 3 newly wired recipe IDs (`redirect`, `browser_sink`, `injection_fingerprint`) validate
 *      against `floorRecipeEnvelopeSchema` and dispatch/verify cleanly through `floor-recipe-engine.ts`
 *      (`retestPersistedRecipe` + `recipeSpecRecord`).
 *  (b) All 5 retired legacy VM kinds (`dns_takeover`, `tls_audit`, `browser_dom`, `ws_chain`,
 *      `upload_probe`) fail closed with `verdict: 'dismissed'` and
 *      `reason: 'retired_legacy_spec_kind: use kovo_verify'` without touching transport/browser.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { floorRecipeEnvelopeSchema, floorRecipeIds } from '../src/replay-spec.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { retestPersistedRecipe } from '../src/server/floor-recipe-engine.ts'
import { RETIRED_LEGACY_SPEC_KINDS, RETIRED_LEGACY_SPEC_REASON, verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const origin = 'http://127.0.0.1:4391'
const actor = { handle: 'anonymous', role: 'anonymous' as const }

function labGrant(tier: 1 | 2 | 3 = 3) {
  return makeLabGrant(origin, { tier, isStateChangeApproved: () => true })
}

test('Cut 3c recipe wiring: redirect, browser_sink, and injection_fingerprint persist and retest cleanly through floor-recipe-engine', async () => {
  for (const id of ['redirect', 'browser_sink', 'injection_fingerprint'] as const) {
    assert.ok((floorRecipeIds as readonly string[]).includes(id), `floorRecipeIds missing ${id}`)
  }

  let fixed = false
  const broker = new RequestBroker({
    transport: async url => {
      if (url.pathname === '/login') {
        const next = url.searchParams.get('next') ?? ''
        if (!fixed && next.startsWith('https://')) {
          return { status: 302, headers: { location: next }, body: '' }
        }
        return { status: 302, headers: { location: '/dashboard' }, body: '' }
      }
      if (url.pathname === '/search') {
        const q = url.searchParams.get('q') ?? ''
        if (!fixed && q.includes("'")) {
          return { status: 500, headers: { 'content-type': 'text/plain' }, body: 'SQLITE_ERROR: near "widgets": syntax error' }
        }
        return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"results":[]}' }
      }
      return { status: 200, headers: { 'content-type': 'text/html' }, body: '<html><body>ok</body></html>' }
    },
  })

  // 1. redirect
  const redirectEnv = floorRecipeEnvelopeSchema.parse({
    recipeId: 'redirect',
    args: {
      origin,
      method: 'GET',
      pathAndQuery: '/login?next=/dashboard',
      controlPathAndQuery: '/login?next=/dashboard',
      probePathAndQuery: '/login?next=https://external.example/landing',
      vulnClass: 'open_redirect',
      actor,
    },
  })
  const redirectRepro = await retestPersistedRecipe({
    envelope: redirectEnv,
    specKind: 'http_chain',
    vulnClass: 'open_redirect',
    endpoint: '/login',
    origin,
    broker,
    grant: labGrant(),
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(redirectRepro.verdict, 'reproduced', redirectRepro.replay.outcome.reason ?? '')

  // 2. injection_fingerprint
  const fpEnv = floorRecipeEnvelopeSchema.parse({
    recipeId: 'injection_fingerprint',
    args: {
      origin,
      method: 'GET',
      pathAndQuery: '/search?q=widgets',
      vulnClass: 'injection',
      actor,
      param: 'q',
      payload: "widgets'",
      family: 'sqli',
    },
  })
  const fpRepro = await retestPersistedRecipe({
    envelope: fpEnv,
    specKind: 'http_chain',
    vulnClass: 'injection',
    endpoint: '/search',
    origin,
    broker,
    grant: labGrant(),
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(fpRepro.verdict, 'reproduced', fpRepro.replay.outcome.reason ?? '')

  // 3. browser_sink
  const browserEnv = floorRecipeEnvelopeSchema.parse({
    recipeId: 'browser_sink',
    args: {
      origin,
      method: 'GET',
      pathAndQuery: '/portal',
      vulnClass: 'dom_xss',
      actor,
      expectSinks: ['dom_xss'],
    },
  })
  const browserRepro = await retestPersistedRecipe({
    envelope: browserEnv,
    specKind: 'browser_chain',
    vulnClass: 'dom_xss',
    endpoint: '/portal',
    origin,
    broker,
    grant: labGrant(),
    signal: AbortSignal.timeout(5_000),
    browserTrace: () => ({ id: 'trace-cut3c-1', origin, sinks: ['dom_xss'] }),
  })
  assert.equal(browserRepro.verdict, 'reproduced', browserRepro.replay.outcome.reason ?? '')

  // Fixed posture transitions all three to 'fixed'
  fixed = true
  const redirectFixed = await retestPersistedRecipe({
    envelope: redirectEnv,
    specKind: 'http_chain',
    vulnClass: 'open_redirect',
    endpoint: '/login',
    origin,
    broker,
    grant: labGrant(),
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(redirectFixed.verdict, 'fixed')

  const fpFixed = await retestPersistedRecipe({
    envelope: fpEnv,
    specKind: 'http_chain',
    vulnClass: 'injection',
    endpoint: '/search',
    origin,
    broker,
    grant: labGrant(),
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(fpFixed.verdict, 'fixed')

  const browserFixed = await retestPersistedRecipe({
    envelope: browserEnv,
    specKind: 'browser_chain',
    vulnClass: 'dom_xss',
    endpoint: '/portal',
    origin,
    broker,
    grant: labGrant(),
    signal: AbortSignal.timeout(5_000),
    browserTrace: () => ({ id: 'trace-cut3c-2', origin, sinks: [] }),
  })
  assert.equal(browserFixed.verdict, 'fixed')
})

test('Cut 3c/3d/3e retirement: all 9 retired legacy spec kinds fail closed without executing legacy VM code', async () => {
  const retiredKinds = [
    'dns_takeover', 'tls_audit', 'browser_dom', 'ws_chain', 'upload_probe',
    'sql_boolean_diff', 'sql_time_diff', 'race_burst', 'browser_chain',
  ] as const
  for (const kind of retiredKinds) {
    assert.ok(RETIRED_LEGACY_SPEC_KINDS.has(kind), `missing retired kind ${kind}`)
  }

  let transportHits = 0
  let browserHits = 0
  const broker = new RequestBroker({
    transport: async () => {
      transportHits += 1
      throw new Error('retired legacy kind must never execute transport')
    },
    dnsResolver: async () => {
      transportHits += 1
      throw new Error('retired legacy kind must never execute DNS')
    },
    tlsInspector: async () => {
      transportHits += 1
      throw new Error('retired legacy kind must never execute TLS')
    },
  })
  const browser = {
    async visitPage() {
      browserHits += 1
      throw new Error('retired legacy kind must never execute browser')
    },
  }
  const backend = new LinuxWorkerBackend()
  const base = {
    version: 1 as const,
    origin,
    title: 'Retired legacy VM check',
    category: 'legacy-check',
    cwe: 'CWE-284',
    severity: 'medium' as const,
    severityRationale: 'Test fixture for Cut 3c-1 fail-closed retirement.',
    impact: 'None — retired spec kind.',
    remediation: 'Use kovo_verify.',
    recheckInstructions: 'Submit via kovo_verify.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
  }

  const specs = [
    { ...base, kind: 'dns_takeover' as const, targetOrigin: origin, probePath: '/' },
    { ...base, kind: 'tls_audit' as const, targetOrigin: origin },
    { ...base, kind: 'browser_dom' as const, targetOrigin: origin, controlPath: '/safe', probePath: '/probe', checkKind: 'dom_xss' as const },
    {
      ...base,
      kind: 'ws_chain' as const,
      steps: [
        { id: 'c', role: 'control' as const, description: 'control', origin, pathAndQuery: '/ws', maxFrames: 2, waitMs: 200 },
        { id: 'p', role: 'probe' as const, description: 'probe', origin, pathAndQuery: '/ws', maxFrames: 2, waitMs: 200 },
      ],
    },
    {
      ...base,
      kind: 'upload_probe' as const,
      requiresTier3Approval: true as const,
      uploadStep: {
        id: 'u', role: 'probe' as const, description: 'upload', origin, method: 'POST' as const,
        pathAndQuery: '/upload', fieldName: 'file', filename: 'a.svg', contentType: 'image/svg+xml', contentTemplate: '<svg>{{upload_nonce}}</svg>',
      },
      fetchStep: {
        id: 'f', role: 'probe' as const, description: 'fetch',
        request: { origin, method: 'GET' as const, pathAndQuery: '/files/1' },
      },
    },
    {
      ...base,
      kind: 'sql_boolean_diff' as const,
      targetOrigin: origin,
      method: 'GET' as const,
      pathAndQuery: '/search?q=1',
      paramName: 'q',
      paramLocation: 'query' as const,
      baselineValue: '1',
      quoteStyle: 'single' as const,
    },
    {
      ...base,
      kind: 'sql_time_diff' as const,
      targetOrigin: origin,
      method: 'GET' as const,
      pathAndQuery: '/search?q=1',
      paramName: 'q',
      paramLocation: 'query' as const,
      baselineValue: '1',
      quoteStyle: 'single' as const,
      dialect: 'postgres' as const,
      delayMs: 1500,
    },
    {
      // Cut 3d retired the raw race VM branch: a legacy race_burst spec must fail closed (it is
      // replaced by the conserved_balance floor recipe).
      ...base,
      kind: 'race_burst' as const,
      burst: [
        { origin, method: 'POST' as const, pathAndQuery: '/giftcards/1/redeem', jsonBody: { amount: 4 } },
        { origin, method: 'POST' as const, pathAndQuery: '/giftcards/1/redeem', jsonBody: { amount: 4 } },
      ],
    },
    {
      // Cut 3e retired the raw browser_chain VM branch: bare browser_chain specs fail closed
      // (navigate/fill/click proofs run via the browser_sink floor recipe envelope).
      ...base,
      kind: 'browser_chain' as const,
      steps: [
        { id: 'c1', role: 'control' as const, description: 'control', origin, pathAndQuery: '/safe', action: 'navigate' as const },
        { id: 'p1', role: 'probe' as const, description: 'probe', origin, pathAndQuery: '/vuln', action: 'navigate' as const },
      ],
    },
  ]

  for (const spec of specs) {
    const result = await verifyReplaySpec({
      spec,
      broker,
      browser: browser as never,
      backend,
      grant: labGrant(3),
      signal: AbortSignal.timeout(5_000),
    })
    assert.equal(result.verdict, 'dismissed', `${spec.kind} must fail closed as dismissed`)
    assert.equal(result.outcome.confirmed, false)
    assert.equal(result.outcome.reason, RETIRED_LEGACY_SPEC_REASON)
    assert.equal(result.exchanges.length, 0)
  }

  assert.equal(transportHits, 0, 'retired legacy VM kinds must perform zero network/DNS/TLS operations')
  assert.equal(browserHits, 0, 'retired legacy VM kinds must perform zero browser operations')
})

test('Cut 3c-2 floorRecipe precedence: sql_boolean_diff with a boolean_or_timing floorRecipe verifies cleanly through ProofReceipt', async () => {
  let fixed = false
  const broker = new RequestBroker({
    transport: async url => {
      if (url.pathname === '/search') {
        const q = url.searchParams.get('id') ?? ''
        const isTrue = !fixed && (q === '1' || /1=1|(\d+)=\1/.test(q))
        const body = isTrue
          ? JSON.stringify({ items: [{ id: 1, name: 'alpha' }, { id: 2, name: 'beta' }] })
          : JSON.stringify({ items: [] })
        return { status: 200, headers: { 'content-type': 'application/json' }, body }
      }
      return { status: 404, headers: { 'content-type': 'text/plain' }, body: 'not found' }
    },
  })
  const backend = new LinuxWorkerBackend()
  const recipe = floorRecipeEnvelopeSchema.parse({
    recipeId: 'boolean_or_timing',
    args: {
      origin,
      method: 'GET',
      pathAndQuery: '/search?id=1',
      controlPathAndQuery: '/search?id=1%20AND%201%3D1',
      probePathAndQuery: '/search?id=1%20AND%201%3D2',
      vulnClass: 'sqli',
      mode: 'boolean',
      param: 'id',
      paramLocation: 'query',
      baselineValue: '1',
      quoteStyle: 'single',
      actor,
    },
  })
  const spec = {
    version: 1 as const,
    kind: 'sql_boolean_diff' as const,
    origin,
    targetOrigin: origin,
    title: 'Boolean differential backed by floorRecipe',
    category: 'injection-input',
    cwe: 'CWE-89',
    severity: 'high' as const,
    severityRationale: 'Verified via boolean_or_timing floor recipe.',
    impact: 'Boolean SQL differential.',
    remediation: 'Parameterize query.',
    recheckInstructions: 'Replay recipe.',
    method: 'GET' as const,
    pathAndQuery: '/search?id=1',
    paramName: 'id',
    paramLocation: 'query' as const,
    baselineValue: '1',
    quoteStyle: 'single' as const,
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
    recipe,
  }

  const confirmed = await verifyReplaySpec({
    spec,
    broker,
    backend,
    grant: labGrant(3),
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(confirmed.verdict, 'confirmed', confirmed.outcome.reason ?? '')
  assert.equal(confirmed.verificationTier, 'runtime_confirmed')
  assert.equal(confirmed.receipt?.verification.confirmed, true)

  fixed = true
  const patched = await verifyReplaySpec({
    spec,
    broker,
    backend,
    grant: labGrant(3),
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(patched.verdict, 'dismissed', patched.outcome.reason ?? '')
})
