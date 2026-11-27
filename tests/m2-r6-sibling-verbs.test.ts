import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { runPhase0Recon } from '../src/server/phase0-recon.ts'
import {
  extractSiblingVerbCandidates,
  probeSiblingVerbCandidates,
} from '../src/server/phase0-sibling-verbs.ts'
import {
  makeLabGrant,
  makeStore,
  setupApprovedRun,
  startHttpFixture,
  withEnv,
} from './v4-tier-helpers.ts'

describe('m2-r6 sibling-verb transfer: extractSiblingVerbCandidates', () => {
  test('returns empty when no :id/<verb> routes exist (proves zero hardcoded wordlists)', () => {
    const origin = 'https://target.example.test'
    const candidates = extractSiblingVerbCandidates({
      endpoints: [
        { origin, method: 'GET', path: '/api/orders' },
        { origin, method: 'GET', path: '/api/orders/123' },
        { origin, method: 'GET', path: '/api/payouts' },
        { origin, method: 'GET', path: '/api/payouts/456' },
        { origin, method: 'GET', path: '/v1/users/:id' },
        { origin, method: 'GET', path: '/api/orders/123/Report.json' },
        { origin, method: 'GET', path: '/api/orders/123/UPPERCASE' },
      ],
      idsByOrigin: {
        [origin]: {
          '/api/orders': ['123'],
          '/api/payouts': ['456'],
          '/v1/users': ['usr_1'],
        },
      },
    })
    assert.deepEqual(candidates, [])
  })

  test('transfers observed verbs across sibling concrete and templated families paired with harvested IDs', () => {
    const origin = 'https://api.example.test'
    const candidates = extractSiblingVerbCandidates({
      endpoints: [
        { origin, method: 'PATCH', path: '/api/orders/123/rebind' },
        { origin, method: 'POST', path: '/api/payouts/456/approve' },
        { origin, method: 'GET', path: '/api/invoices/:invoiceId' },
        { origin, method: 'GET', path: '/api/refunds/:id' },
      ],
      idsByOrigin: {
        [origin]: {
          '/api/invoices': ['inv_789'],
          // /api/refunds intentionally has NO concrete ID -> must never emit literal :id
        },
      },
    })

    const paths = candidates.map(c => c.concretePath)
    assert.ok(paths.includes('/api/payouts/456/rebind'), `expected payouts rebind: ${paths.join(', ')}`)
    assert.ok(paths.includes('/api/orders/123/approve'), `expected orders approve: ${paths.join(', ')}`)
    assert.ok(paths.includes('/api/invoices/inv_789/rebind'), `expected invoices rebind: ${paths.join(', ')}`)
    assert.ok(paths.includes('/api/invoices/inv_789/approve'), `expected invoices approve: ${paths.join(', ')}`)
    assert.ok(!paths.includes('/api/orders/123/rebind'), 'must not re-emit already known verb on orders')
    assert.ok(!paths.includes('/api/payouts/456/approve'), 'must not re-emit already known verb on payouts')
    assert.ok(!paths.some(p => p.includes('/refunds/') || p.includes(':id')), 'must never emit routes without concrete IDs')

    const payoutRebind = candidates.find(c => c.concretePath === '/api/payouts/456/rebind')
    assert.ok(payoutRebind)
    assert.equal(payoutRebind.templatePath, '/api/payouts/:id/rebind')
    assert.equal(payoutRebind.sourceScope, 'same_origin')
    assert.deepEqual(payoutRebind.observedMethods, ['PATCH'])
  })

  test('recovers concrete IDs from observedConcretePathsByOrigin when stored endpoints are normalized', () => {
    const origin = 'https://normalized.example.test'
    const candidates = extractSiblingVerbCandidates({
      endpoints: [
        { origin, method: 'PATCH', path: '/v1/orders/:id/rebind' },
        { origin, method: 'POST', path: '/v1/payouts/:id/approve' },
      ],
      observedConcretePathsByOrigin: {
        [origin]: ['/v1/orders/ord_11/rebind', '/v1/payouts/pay_22/approve'],
      },
    })
    assert.deepEqual(
      candidates.map(c => c.concretePath).sort(),
      ['/v1/orders/ord_11/approve', '/v1/payouts/pay_22/rebind'],
    )
  })

  test('prioritizes same-origin verbs before sibling-origin shared-prefix verbs and enforces caps', () => {
    const originA = 'https://orders.example.test'
    const originB = 'https://payouts.example.test'
    const outOfScope = 'https://outsider.example.test'

    const candidates = extractSiblingVerbCandidates({
      endpoints: [
        { origin: originA, method: 'POST', path: '/v1/orders/101/rebind' },
        { origin: originA, method: 'POST', path: '/v1/invoices/102/archive' },
        { origin: originB, method: 'POST', path: '/v1/payouts/201/approve' },
        { origin: originB, method: 'POST', path: '/v1/ledgers/202/settle' },
        { origin: outOfScope, method: 'POST', path: '/v1/secrets/999/exfil' },
      ],
      approvedOrigins: [originA, originB],
      maxCandidatesPerOrigin: 3,
      maxTotalCandidates: 5,
    })

    assert.equal(candidates.length, 5)
    assert.ok(candidates.every(c => c.origin !== outOfScope && c.verb !== 'exfil'), 'out-of-scope origin excluded')

    const countA = candidates.filter(c => c.origin === originA).length
    const countB = candidates.filter(c => c.origin === originB).length
    assert.ok(countA <= 3 && countB <= 3, `per-origin cap respected (${countA}, ${countB})`)

    const firstSiblingIdx = candidates.findIndex(c => c.sourceScope === 'sibling_origin')
    const lastSameIdx = candidates.map(c => c.sourceScope).lastIndexOf('same_origin')
    assert.ok(firstSiblingIdx > lastSameIdx, 'all same-origin candidates precede sibling-origin candidates')
    assert.ok(candidates.some(c => c.sourceScope === 'sibling_origin'), 'sibling-origin transfer included under shared /v1 prefix')
  })
})

describe('m2-r6 sibling-verb transfer: probeSiblingVerbCandidates e2e', () => {
  test('discovers sibling verbs via OPTIONS Allow & GET 405, ignores 404s, stays strictly read-only, skips out-of-scope, and never uses elevated personas', async (t: TestContext) => {
    const received: Array<{ method: string; url: string; auth: string | undefined }> = []
    const fx = await startHttpFixture(t, (req, _body, res) => {
      const method = req.method ?? 'GET'
      const url = req.url ?? '/'
      const auth = typeof req.headers.authorization === 'string' ? req.headers.authorization : undefined
      received.push({ method, url, auth })

      // Discovered via OPTIONS with Allow header
      if (url === '/api/payouts/456/rebind') {
        if (method === 'OPTIONS') {
          res.statusCode = 204
          res.setHeader('Allow', 'PATCH, GET, OPTIONS')
          res.end()
          return
        }
        res.statusCode = 405
        res.setHeader('Allow', 'PATCH, GET')
        res.end()
        return
      }

      // Discovered via OPTIONS 404 -> GET 405 with Allow header
      if (url === '/api/invoices/789/rebind') {
        if (method === 'OPTIONS') {
          res.statusCode = 404
          res.end('not found')
          return
        }
        if (method === 'GET') {
          res.statusCode = 405
          res.setHeader('Allow', 'POST')
          res.end('method not allowed')
          return
        }
      }

      // Discovered via OPTIONS 501 -> GET 405 without Allow (infers observed PATCH/POST)
      if (url === '/api/invoices/789/approve') {
        if (method === 'OPTIONS') {
          res.statusCode = 501
          res.end('not implemented')
          return
        }
        if (method === 'GET') {
          res.statusCode = 405
          res.end('method not allowed')
          return
        }
      }

      // CORS-style OPTIONS 204 (no Allow) + GET 404 -> MUST be rejected (not registered)
      if (url === '/api/orders/123/corsghost') {
        if (method === 'OPTIONS') {
          res.statusCode = 204
          res.end()
          return
        }
        res.statusCode = 404
        res.end('not found')
        return
      }

      // True 404 on both OPTIONS and GET
      res.statusCode = 404
      res.end('not found')
    })

    let outOfScopeHits = 0
    const outOfScopeFx = await startHttpFixture(t, (_req, _body, res) => {
      outOfScopeHits += 1
      res.statusCode = 200
      res.setHeader('Allow', 'POST')
      res.end('ok')
    })

    const { storage } = makeStore(t, 'kovo-m2-r6-probe-')
    const { runId, run } = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 400 })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const baseGrant = makeLabGrant(fx.origin)
    const personasMap = new Map([
      ['admin', {
        id: 'p-admin',
        handle: 'admin',
        roleLabel: 'admin',
        privilege: 'admin' as const,
        originAllowlist: [fx.origin],
        authKind: 'bearer' as const,
        headerName: null,
        secret: 'admin-secret-token',
        canaryMarkers: [],
      }],
      ['member', {
        id: 'p-member',
        handle: 'member',
        roleLabel: 'user',
        privilege: 'member' as const,
        originAllowlist: [fx.origin],
        authKind: 'bearer' as const,
        headerName: null,
        secret: 'low-priv-member-token',
        canaryMarkers: [],
      }],
    ])
    const grant: Grant = {
      ...baseGrant,
      personas: personasMap,
    }

    const candidates = [
      ...extractSiblingVerbCandidates({
        endpoints: [
          { origin: fx.origin, method: 'PATCH', path: '/api/orders/123/rebind' },
          { origin: fx.origin, method: 'POST', path: '/api/payouts/456/approve' },
          { origin: fx.origin, method: 'GET', path: '/api/invoices/789' },
          { origin: fx.origin, method: 'GET', path: '/api/payouts/456/corsghost' },
        ],
      }),
      {
        origin: outOfScopeFx.origin,
        prefix: '/api',
        resource: 'payouts',
        concreteId: '456',
        verb: 'rebind',
        concretePath: '/api/payouts/456/rebind',
        templatePath: '/api/payouts/:id/rebind',
        sourceScope: 'sibling_origin' as const,
        observedMethods: ['PATCH'],
      },
    ]

    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => probeSiblingVerbCandidates({
      storage,
      runId,
      scopeRevision: run.scopeRevision,
      broker,
      grant,
      signal: AbortSignal.timeout(10_000),
      candidates,
      personas: ['admin', 'member'],
    }))

    // Strictly read-only HTTP methods only
    assert.ok(received.length > 0)
    assert.ok(
      received.every(r => r.method === 'OPTIONS' || r.method === 'GET'),
      `mutating HTTP method sent during sibling-verb discovery: ${received.map(r => `${r.method} ${r.url}`).join(', ')}`,
    )
    // Low-privilege persona only (NEVER admin)
    assert.ok(
      received.every(r => r.auth === 'Bearer low-priv-member-token'),
      `expected only low-priv persona auth, got: ${received.map(r => r.auth).join(', ')}`,
    )
    // Out-of-scope origin completely skipped
    assert.equal(outOfScopeHits, 0)
    assert.equal(res.skippedOutOfScope, 1)

    const endpoints = storage.listEndpoints(runId, { origin: fx.origin })
    const routeKeys = new Set(endpoints.map(e => `${e.method} ${e.pathTemplate}`))

    assert.ok(routeKeys.has('PATCH /api/payouts/:id/rebind'), 'discovered PATCH via OPTIONS Allow')
    assert.ok(routeKeys.has('GET /api/payouts/:id/rebind'), 'discovered GET via OPTIONS Allow')
    assert.ok(routeKeys.has('POST /api/invoices/:id/rebind'), 'discovered POST via OPTIONS 404 -> GET 405 Allow')
    assert.ok(routeKeys.has('POST /api/invoices/:id/approve'), 'discovered POST via OPTIONS 501 -> GET 405 inferred')
    assert.ok(!routeKeys.has('GET /api/orders/:id/approve'), '404 route must not be registered')
    assert.ok(!routeKeys.has('POST /api/orders/:id/approve'), '404 route must not be registered')
    assert.ok(!routeKeys.has('GET /api/orders/:id/corsghost'), 'CORS Allow-less OPTIONS 204 + GET 404 must not be registered')

    // Zero conventional endpoints counted
    const conventionalRow = storage.client.prepare(
      `SELECT COUNT(*) AS cnt FROM endpoints WHERE run_id = ? AND source = 'conventional'`,
    ).get(runId) as { cnt: number }
    assert.equal(conventionalRow.cnt, 0)

    // Path param :id recorded for discovered endpoint
    const payoutRebindEp = endpoints.find(e => e.method === 'PATCH' && e.pathTemplate === '/api/payouts/:id/rebind')
    assert.ok(payoutRebindEp)
    const params = storage.listEndpointParams(runId, payoutRebindEp.id)
    assert.ok(params.some(p => p.name === 'id' && p.location === 'path' && p.isObjectId))
  })

  test('never falls back to an admin/owner persona when no low-privilege persona exists', async (t: TestContext) => {
    const authHeadersSeen: Array<string | undefined> = []
    const fx = await startHttpFixture(t, (req, _body, res) => {
      authHeadersSeen.push(typeof req.headers.authorization === 'string' ? req.headers.authorization : undefined)
      if (req.url === '/api/payouts/456/rebind' && req.method === 'OPTIONS') {
        res.statusCode = 204
        res.setHeader('Allow', 'PATCH')
        res.end()
        return
      }
      res.statusCode = 404
      res.end()
    })

    const { storage } = makeStore(t, 'kovo-m2-r6-priv-')
    const { runId, run } = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 200 })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const grant: Grant = {
      ...makeLabGrant(fx.origin),
      personas: new Map([
        ['admin', {
          id: 'p-admin-only',
          handle: 'admin',
          roleLabel: 'administrator',
          privilege: 'admin' as const,
          originAllowlist: [fx.origin],
          authKind: 'bearer' as const,
          headerName: null,
          secret: 'admin-only-token',
          canaryMarkers: [],
        }],
      ]),
    }

    const candidates = extractSiblingVerbCandidates({
      endpoints: [
        { origin: fx.origin, method: 'PATCH', path: '/api/orders/123/rebind' },
        { origin: fx.origin, method: 'POST', path: '/api/payouts/456/approve' },
      ],
    })

    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => probeSiblingVerbCandidates({
      storage,
      runId,
      scopeRevision: run.scopeRevision,
      broker,
      grant,
      signal: AbortSignal.timeout(10_000),
      candidates,
      personas: ['admin'],
    }))

    assert.ok(authHeadersSeen.length > 0)
    assert.ok(authHeadersSeen.every(h => h === undefined), `admin token must never be used: ${authHeadersSeen.join(', ')}`)
  })
})

describe('m2-r6 sibling-verb transfer: runPhase0Recon grey-box integration', () => {
  test('automatically transfers observed route-map verb to sibling collection family during Phase-0 recon', async (t: TestContext) => {
    const seenMethodsForHidden: string[] = []
    const routeMap = {
      apiPrefix: '/v1',
      routes: {
        ordersList: { method: 'GET', path: '/v1/orders' },
        orderRebind: { method: 'PATCH', path: '/v1/orders/:id/rebind' },
        payoutsList: { method: 'GET', path: '/v1/payouts' },
        payoutApprove: { method: 'POST', path: '/v1/payouts/:id/approve' },
      },
    }

    const fx = await startHttpFixture(t, (req, _body, res) => {
      const method = req.method ?? 'GET'
      const url = req.url ?? '/'

      if (url === '/') {
        res.setHeader('Content-Type', 'text/html')
        res.end('<html><body><a href="/v1/orders">Orders</a><a href="/v1/payouts">Payouts</a><script src="/app.js"></script></body></html>')
        return
      }
      if (url === '/app.js') {
        res.setHeader('Content-Type', 'application/javascript')
        res.end(`fetch('/config.json'); fetch('/v1/orders'); fetch('/v1/payouts');`)
        return
      }
      if (url === '/config.json') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify(routeMap))
        return
      }
      if (url === '/v1/orders' && method === 'GET') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ items: [{ id: 'ord_101' }] }))
        return
      }
      if (url === '/v1/payouts' && method === 'GET') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ items: [{ id: 'pay_202' }] }))
        return
      }
      // Hidden sibling verb route on payouts (NOT in /config.json or /app.js!)
      if (url === '/v1/payouts/pay_202/rebind') {
        seenMethodsForHidden.push(method)
        if (method === 'OPTIONS') {
          res.statusCode = 200
          res.setHeader('Allow', 'PATCH, GET')
          res.end('PATCH,GET')
          return
        }
        if (method === 'GET') {
          res.statusCode = 405
          res.setHeader('Allow', 'PATCH')
          res.end()
          return
        }
      }
      res.statusCode = 404
      res.end('not found')
    })

    const { storage } = makeStore(t, 'kovo-m2-r6-phase0-')
    const { runId, run } = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 600 })
    const broker = new RequestBroker({ rejectUnauthorized: false })

    const recon = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => runPhase0Recon({
      storage,
      runId,
      scopeRevision: run.scopeRevision,
      tier: 1,
      origins: [fx.origin],
      broker,
      grant: makeLabGrant(fx.origin, { tier: 1 }),
      signal: AbortSignal.timeout(15_000),
      perOriginCap: 80,
    }))

    assert.ok(recon.endpointsDiscovered > 0)
    assert.ok(seenMethodsForHidden.length > 0, 'Phase-0 should have probed hidden sibling verb /v1/payouts/pay_202/rebind')
    assert.ok(
      seenMethodsForHidden.every(m => m === 'OPTIONS' || m === 'GET'),
      `only read-only methods allowed, got: ${seenMethodsForHidden.join(', ')}`,
    )

    const endpoints = storage.listEndpoints(runId, { origin: fx.origin })
    const hiddenPatch = endpoints.find(e => e.method === 'PATCH' && e.pathTemplate === '/v1/payouts/:id/rebind')
    assert.ok(hiddenPatch, 'PATCH /v1/payouts/:id/rebind should be discovered and persisted in storage')
    assert.equal(hiddenPatch.source, 'surface_probe')

    // Producer -> consumer API dependency edge recorded for /v1/payouts -> /v1/payouts/:id/rebind
    const deps = storage.listApiDependencies(runId)
    const payoutsProducer = endpoints.find(e => e.pathTemplate === '/v1/payouts')
    assert.ok(payoutsProducer)
    assert.ok(
      deps.some(d => d.producerEndpointId === payoutsProducer.id && d.consumerEndpointId === hiddenPatch.id),
      'expected api_dependencies edge linking /v1/payouts producer to discovered sibling verb consumer',
    )

    // Verify conventionalEndpointsProbed stays 0
    const conventionalRow = storage.client.prepare(
      `SELECT COUNT(*) AS cnt FROM endpoints WHERE run_id = ? AND source = 'conventional'`,
    ).get(runId) as { cnt: number }
    assert.equal(conventionalRow.cnt, 0)
  })
})
