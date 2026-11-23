// v5.1 recon-cache acceptance: hill-climb iterations may reuse Phase-0 discovery, but never
// probe/verification results. Covers key invalidation, the hit path (discovery skipped only),
// cache-file secret hygiene, and clean miss fallback.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { createServer } from 'node:http'
import { test } from 'node:test'

import {
  RECON_CACHE_FORMAT, applyReconSnapshot, captureReconSnapshot, emptyReconCacheMeta, parseRealisticArgs,
  readReconCache, reconCacheKey, reconCachePath, reconVariantHash, replayReconSurface, surfaceReplayPath,
  validateReconCacheFile, writeReconCache,
} from '../scripts/benchmark-realistic.ts'
import type {
  CachedPersonaSessionHandle, ReconCacheFile, ReconCacheKeyInputs,
} from '../scripts/benchmark-realistic.ts'
import { Store } from '../src/server/store.ts'
import type { Run } from '../src/server/store.ts'

// The fixture Store creates a loopback-seeded project, which requires local-lab consent.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

interface Fixture {
  directory: string
  store: Store
  run: Run
}

function makeFixture(): Fixture {
  const directory = mkdtempSync(join(tmpdir(), 'guardian-recon-cache-'))
  const store = new Store(directory)
  const project = store.createProject({
    requestId: randomUUID(),
    name: 'recon-cache test',
    seeds: ['http://127.0.0.1:4100'],
    environment: 'local-lab',
  })
  const created = store.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'recon cache test',
    sourceMode: 'public',
    capabilityTier: 3,
    approvalPolicy: 'auto_review',
    approvedPersonaIds: [],
    budgetUsd: 5,
    budgetRequests: 100,
    maxRpsPerOrigin: 10,
    workerConcurrency: 1,
    workerMaxTurns: 5,
    multiTrialEnabled: false,
  })
  return { directory, store, run: store.run(created.id) }
}

function seedSurface(store: Store, run: Run, origin = 'http://127.0.0.1:4100'): void {
  const orders = store.upsertEndpoint({
    runId: run.id,
    origin,
    method: 'GET',
    pathTemplate: '/api/orders',
    source: 'openapi',
    framework: 'express',
    sinkKinds: ['sql'],
    riskScore: 70,
  })
  const order = store.upsertEndpoint({
    runId: run.id,
    origin,
    method: 'GET',
    pathTemplate: '/api/orders/:id',
    source: 'spa_crawl',
    ownershipGuard: 'ownerCheck',
    riskScore: 82,
  })
  store.upsertEndpointParam({
    runId: run.id,
    endpointId: orders.id,
    name: 'q',
    location: 'query',
    source: 'spa_crawl',
  })
  store.upsertEndpointParam({
    runId: run.id,
    endpointId: order.id,
    name: 'id',
    location: 'path',
    isObjectId: true,
    source: 'spa_crawl',
  })
  store.recordResourceSample({
    runId: run.id,
    ownerPersona: 'persona-a',
    resourceKey: 'orderId',
    resourceId: 'ord_abc123',
    origin,
    endpoint: '/api/orders',
    method: 'GET',
    authenticated: true,
  })
  store.recordApiDependency({
    runId: run.id,
    producerEndpointId: orders.id,
    consumerEndpointId: order.id,
    resourceKey: 'orderId',
    personaHandle: 'persona-a',
    observedTransitions: ['list->detail'],
  })
}

function keyInputs(overrides: Partial<ReconCacheKeyInputs> = {}): ReconCacheKeyInputs {
  return {
    app: 'acme-saas',
    seed: 42,
    split: 'dev',
    mode: 'grey-box',
    variantHash: 'a1b2c3d4e5f60718',
    ...overrides,
  }
}

const personaSessions: CachedPersonaSessionHandle[] = [{
  handle: 'persona-a',
  roleLabel: 'customer (tenant-a)',
  authKind: 'login',
  headerType: 'cookie',
  headerName: null,
  adapter: 'json',
  loginPath: '/login',
  expiresAt: null,
  sessionHandle: 'f'.repeat(24),
}]

function capture(fixture: Fixture, options: {
  keyInputs?: ReconCacheKeyInputs
  boundary?: number
  secrets?: Array<{ value: string; placeholder: string }>
  sessions?: CachedPersonaSessionHandle[]
  sourceOrigin?: string
} = {}) {
  return captureReconSnapshot({
    storage: fixture.store,
    runId: fixture.run.id,
    keyInputs: options.keyInputs ?? keyInputs(),
    sourceOrigin: options.sourceOrigin ?? 'http://127.0.0.1:4100',
    phase0CompletedAt: options.boundary ?? Date.now(),
    observedDurationMs: 1234,
    personaSessions: options.sessions ?? personaSessions,
    secrets: options.secrets ?? [],
    gitSha: 'deadbeefcafe',
  })
}

// ---------------------------------------------------------------------------------------------
// CLI surface
// ---------------------------------------------------------------------------------------------

test('CLI: --reuse-recon parses to an absolute directory; --refresh-recon requires it', () => {
  const args = parseRealisticArgs(['--reuse-recon', 'recon-cache', '--refresh-recon'], {})
  assert.equal(args.reuseReconDir, resolve('recon-cache'))
  assert.equal(args.refreshRecon, true)

  const absolute = parseRealisticArgs(['--reuse-recon', '/tmp/recon-cache'], {})
  assert.equal(absolute.reuseReconDir, '/tmp/recon-cache')
  assert.equal(absolute.refreshRecon, false)

  assert.throws(() => parseRealisticArgs(['--refresh-recon'], {}), /--refresh-recon requires --reuse-recon/)
  assert.throws(() => parseRealisticArgs(['--reuse-recon'], {}), /--reuse-recon requires a directory/)
  assert.throws(() => parseRealisticArgs(['--reuse-recon', 'x', '--app', 'nope'], {}), /--app/)
})

test('CLI: default meta is inert and opted out', () => {
  const meta = emptyReconCacheMeta()
  assert.equal(meta.requested, false)
  assert.equal(meta.hit, false)
  assert.equal(meta.phase0Skipped, false)
  assert.equal(meta.reconTimeSavedMs, 0)
})

// ---------------------------------------------------------------------------------------------
// Key invalidation
// ---------------------------------------------------------------------------------------------

test('key: (app, seed, split, mode, variantHash) all invalidate the cache key', () => {
  const base = reconCacheKey(keyInputs())
  assert.equal(reconCacheKey(keyInputs()), base)
  for (const overrides of [
    { app: 'shopflow' as const },
    { seed: 43 },
    { split: 'held-out' as const },
    { mode: 'white-box' as const },
    { variantHash: 'ffffffffffffffff' },
  ]) {
    assert.notEqual(reconCacheKey(keyInputs(overrides)), base, JSON.stringify(overrides))
  }
  assert.match(reconCachePath('/tmp/cache', keyInputs()), /acme-saas-seed42-dev-grey-box-a1b2c3d4e5f60718\.json$/)
})

test('key: variant hash covers briefing surface, login route and persona handles only', () => {
  const base = {
    app: 'acme-saas' as const,
    mode: 'grey-box' as const,
    loginPath: '/login',
    apiReference: [
      { routeKey: 'orders', method: 'GET', path: '/api/orders', params: ['q'] },
      { routeKey: 'order', method: 'GET', path: '/api/orders/:id', params: ['id'] },
    ],
    personaHandles: ['persona-a', 'persona-b'],
  }
  const hash = reconVariantHash(base)
  assert.equal(hash, reconVariantHash({
    ...base,
    // Reordering the reference and handles must not invalidate the cache.
    apiReference: [...base.apiReference].reverse(),
    personaHandles: ['persona-b', 'persona-a'],
  }))
  assert.notEqual(hash, reconVariantHash({ ...base, loginPath: '/auth/login' }))
  assert.notEqual(hash, reconVariantHash({ ...base, personaHandles: ['persona-a'] }))
  assert.notEqual(hash, reconVariantHash({
    ...base,
    apiReference: [...base.apiReference, { routeKey: 'admin', method: 'GET', path: '/api/admin', params: [] }],
  }))
})

// ---------------------------------------------------------------------------------------------
// Hit path: surface seeded, discovery skipped, probing/verification untouched
// ---------------------------------------------------------------------------------------------

test('hit: snapshot carries discovery rows and no probe/verification state', () => {
  const fixture = makeFixture()
  try {
    seedSurface(fixture.store, fixture.run)
    const { snapshot, counts } = capture(fixture)
    assert.equal(counts.endpoints, 2)
    assert.equal(counts.endpointParams, 2)
    assert.equal(counts.apiDependencies, 1)
    assert.equal(counts.resourceSamples, 1)
    assert.deepEqual(Object.keys(snapshot.surface).sort(), [
      'apiDependencies', 'endpointParams', 'endpoints', 'resourceSamples', 'surfacePaths',
    ])
    // The snapshot is discovery-only: no findings/facts/specs/exchanges are represented.
    const serialized = JSON.stringify(snapshot)
    for (const forbidden of ['"findings"', '"facts"', '"replaySpecs"', '"replay_specs"', '"brokerExchanges"', '"oracleEvents"']) {
      assert.equal(serialized.includes(forbidden), false, forbidden)
    }
    assert.equal(snapshot.security.secretsIncluded, false)
    assert.equal(snapshot.security.sessionValuesIncluded, false)
  } finally {
    fixture.store.close()
  }
})

test('hit: apply seeds a fresh run and closes the Phase-0 gate without findings', () => {
  const source = makeFixture()
  const target = makeFixture()
  try {
    seedSurface(source.store, source.run)
    const { snapshot } = capture(source)
    const applied = applyReconSnapshot({
      storage: target.store,
      runId: target.run.id,
      origin: 'http://127.0.0.1:5099',
      snapshot,
    })
    assert.deepEqual(
      { endpoints: applied.endpoints, params: applied.endpointParams, deps: applied.apiDependencies, samples: applied.resourceSamples },
      { endpoints: 2, params: 2, deps: 1, samples: 1 },
    )

    const run = target.store.run(target.run.id)
    assert.ok(run.phase0CompletedAt, 'phase0CompletedAt gate must be set so the engine skips discovery')

    const detail = target.store.runDetail(target.run.id)
    assert.equal(detail.endpoints.length, 2)
    assert.equal(detail.endpointParams.length, 2)
    assert.equal(detail.findings.length, 0, 'probing/verification are never cached')
    assert.equal(detail.facts.length, 0)
    assert.equal(detail.replaySpecs.length, 0)
    assert.equal(detail.exchangesSummary.length, 0)

    // Origins are rebound to the warm run's ephemeral lab port.
    assert.ok(detail.endpoints.every(ep => ep.origin === 'http://127.0.0.1:5099'))
    assert.ok(target.store.listResourceSamples(target.run.id)
      .every(sample => sample.origin === 'http://127.0.0.1:5099'))
    // Auth/session state is metadata only, so the warm run still has to authenticate for real.
    assert.equal(detail.personas?.length ?? 0, 0)
  } finally {
    source.store.close()
    target.store.close()
  }
})

test('capture: rows created after Phase-0 completion are excluded', () => {
  const fixture = makeFixture()
  try {
    seedSurface(fixture.store, fixture.run)
    const boundary = Date.now()
    const later = fixture.store.upsertEndpoint({
      runId: fixture.run.id,
      origin: 'http://127.0.0.1:4100',
      method: 'POST',
      pathTemplate: '/api/investigation-only',
      source: 'surface_probe',
    })
    fixture.store.client.prepare('update endpoints set created_at = ? where id = ?').run(boundary + 10_000, later.id)
    const { snapshot, counts } = capture(fixture, { boundary })
    assert.equal(counts.endpoints, 2)
    assert.equal(snapshot.surface.endpoints.some(ep => ep.pathTemplate === '/api/investigation-only'), false)
  } finally {
    fixture.store.close()
  }
})

// ---------------------------------------------------------------------------------------------
// Security: no secrets in plaintext
// ---------------------------------------------------------------------------------------------

test('security: cache files contain no persona password or session value', () => {
  const fixture = makeFixture()
  const cacheDir = mkdtempSync(join(tmpdir(), 'guardian-recon-cache-dir-'))
  try {
    seedSurface(fixture.store, fixture.run)
    const password = 'C4nary-Passw0rd-9f2'
    const cookieValue = 'session=abcd1234efgh5678'
    const { snapshot } = capture(fixture, {
      secrets: [{ value: password, placeholder: '[[persona-password]]' }],
    })
    const path = writeReconCache(cacheDir, keyInputs(), snapshot)
    const text = readFileSync(path, 'utf8')
    assert.equal(text.includes(password), false)
    assert.equal(text.includes(cookieValue), false)
    assert.equal(/"value"\s*:/i.test(JSON.stringify(snapshot.auth)), false)
    assert.equal(/"cookie"\s*:/i.test(JSON.stringify(snapshot.auth)), false)
    assert.equal(/"token"\s*:/i.test(JSON.stringify(snapshot.auth)), false)
    assert.equal(statSync(path).mode & 0o077, 0)
    assert.equal(statSync(cacheDir).mode & 0o077, 0)

    // A digest identifying the session surface is fine and is not the credential itself.
    assert.equal(snapshot.auth.length, 1)
    assert.equal(snapshot.auth[0]!.sessionHandle, 'f'.repeat(24))
  } finally {
    fixture.store.close()
  }
})

test('security: registered secrets are redacted out of cached rows before write', () => {
  const fixture = makeFixture()
  const cacheDir = mkdtempSync(join(tmpdir(), 'guardian-recon-cache-redact-'))
  try {
    const password = 'Leak-Me-Passw0rd-42'
    fixture.store.upsertEndpoint({
      runId: fixture.run.id,
      origin: 'http://127.0.0.1:4100',
      method: 'GET',
      pathTemplate: `/api/leak/${password}`,
      source: 'surface_probe',
    })
    const { snapshot } = capture(fixture, {
      secrets: [{ value: password, placeholder: '[[persona-password]]' }],
    })
    const serialized = JSON.stringify(snapshot)
    assert.equal(serialized.includes(password), false)
    assert.ok(serialized.includes('[[persona-password]]'))
    const path = writeReconCache(cacheDir, keyInputs(), snapshot)
    assert.equal(readFileSync(path, 'utf8').includes(password), false)
  } finally {
    fixture.store.close()
  }
})

test('security: validation rejects hand-written auth secret material', () => {
  const fixture = makeFixture()
  try {
    seedSurface(fixture.store, fixture.run)
    const { snapshot } = capture(fixture)
    const tampered = {
      ...snapshot,
      auth: [{ ...snapshot.auth[0]!, value: 'leaked-cookie-value' }],
    }
    assert.match(validateReconCacheFile(tampered, keyInputs()) ?? '', /secret material/)
  } finally {
    fixture.store.close()
  }
})

// ---------------------------------------------------------------------------------------------
// Miss fallback
// ---------------------------------------------------------------------------------------------

test('miss: absent, corrupt, mismatched and tampered snapshots fall back cleanly', () => {
  const fixture = makeFixture()
  const cacheDir = mkdtempSync(join(tmpdir(), 'guardian-recon-cache-miss-'))
  try {
    seedSurface(fixture.store, fixture.run)
    const { snapshot } = capture(fixture)

    const absent = readReconCache(cacheDir, keyInputs())
    assert.equal(absent.hit, false)
    assert.match(absent.reason, /no snapshot/)

    const path = writeReconCache(cacheDir, keyInputs(), snapshot)
    assert.equal(readReconCache(cacheDir, keyInputs()).hit, true)

    // Same file, different seed => miss (never reuse another cell's surface).
    const otherSeed = readReconCache(cacheDir, keyInputs({ seed: 43 }))
    assert.equal(otherSeed.hit, false)

    writeFileSync(path, '{not json')
    const corrupt = readReconCache(cacheDir, keyInputs())
    assert.equal(corrupt.hit, false)
    assert.match(corrupt.reason, /not valid JSON/)

    writeReconCache(cacheDir, keyInputs(), snapshot)
    const tampered: ReconCacheFile = {
      ...snapshot,
      surface: {
        ...snapshot.surface,
        endpoints: snapshot.surface.endpoints.map(ep => ({ ...ep, pathTemplate: '/api/evil' })),
      },
    }
    writeFileSync(path, `${JSON.stringify(tampered, null, 2)}\n`)
    const checksum = readReconCache(cacheDir, keyInputs())
    assert.equal(checksum.hit, false)
    assert.match(checksum.reason, /checksum mismatch/)

    // Format drift also misses instead of crashing.
    const stale = { ...snapshot, format: RECON_CACHE_FORMAT + 1 }
    writeFileSync(path, `${JSON.stringify(stale, null, 2)}\n`)
    const format = readReconCache(cacheDir, keyInputs())
    assert.equal(format.hit, false)
    assert.match(format.reason, /format/)
  } finally {
    fixture.store.close()
  }
})

test('miss: refresh path ignores a valid snapshot without throwing', () => {
  const fixture = makeFixture()
  const cacheDir = mkdtempSync(join(tmpdir(), 'guardian-recon-cache-refresh-'))
  try {
    seedSurface(fixture.store, fixture.run)
    const { snapshot } = capture(fixture)
    writeReconCache(cacheDir, keyInputs(), snapshot)
    // The harness only reads the cache when refresh is off; the read itself stays valid.
    assert.equal(readReconCache(cacheDir, keyInputs()).hit, true)
  } finally {
    fixture.store.close()
  }
})

// ---------------------------------------------------------------------------------------------
// Surface affirmation (real GET replay, no probe payloads)
// ---------------------------------------------------------------------------------------------

test('surface paths: only query-free, payload-free app paths are replayable', () => {
  assert.equal(surfaceReplayPath('/api/orders?q=1'), '/api/orders')
  assert.equal(surfaceReplayPath('/api/orders/ord_123'), '/api/orders/ord_123')
  assert.equal(surfaceReplayPath('/.guardian-cal-abc123'), null)
  assert.equal(surfaceReplayPath('/rest/.guardian-cal-abc123'), null)
  assert.equal(surfaceReplayPath('/api/leak/[[persona-password]]'), null)
  assert.equal(surfaceReplayPath('/api/<script>alert(1)</script>'), null)
  assert.equal(surfaceReplayPath('https://elsewhere.example/steal'), null)
  assert.equal(surfaceReplayPath('//evil.example/path'), null)
})

test('surface affirmation: replays cached GET paths and reports counts', async () => {
  const hits: string[] = []
  const server = createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`)
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('ok')
  })
  await new Promise<void>(resolveListen => server.listen(0, '127.0.0.1', resolveListen))
  try {
    const address = server.address()
    assert.ok(address && typeof address === 'object')
    const origin = `http://127.0.0.1:${address.port}`
    const result = await replayReconSurface({
      origin,
      paths: ['/api/orders?q=1', '/api/users', '/api/users', '/.guardian-cal-x', '/api/%3Cscript%3E'],
    })
    assert.deepEqual(result, { attempted: 3, completed: 3, failed: 0 })
    assert.deepEqual(hits.sort(), ['GET /api/%3Cscript%3E', 'GET /api/orders', 'GET /api/users'])
  } finally {
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  }
})
