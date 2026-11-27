/**
 * Kovo v6 — product-side paging (lossless ingestion view + probe-candidate selection).
 *
 * Regression for the monorepo fixture finding: Phase-0 declared-surface ingestion read only the
 * store's default 500-row page (reporting ~246 of 2,565 declared ops), and probe selection was
 * built from a hard `limit: 5000` read. Both views are now paged through the store's stable
 * (risk, coverage, id) ordering; the probe cap still bounds probes, never selection.
 */
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  DETERMINISTIC_PROBE_CAP,
  ENGINE_PROBE_CAP,
  probeSelectionMetrics,
  selectProbeCandidates,
} from '../src/server/execution.ts'
import {
  countTolerantOpenApiOperations,
  harvestTolerantOpenApiOperations,
  ingestDeclaredApiSurface,
  listEndpointsPaged,
} from '../src/server/phase0-recon.ts'
import { Store } from '../src/server/store.ts'

const ORIGIN = 'https://v7.example'

interface Fixture {
  dir: string
  store: Store
  runId: string
}

function makeStore(t: { after: (fn: () => void) => void }, label: string): Fixture {
  const dir = mkdtempSync(join(tmpdir(), `kovo-v6-paging-${label}-`))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const store = new Store(dir)
  t.after(() => store.close())
  const { id: projectId } = store.createProject({
    requestId: randomUUID(), name: `v6 paging ${label}`, seeds: [ORIGIN], environment: 'public',
  })
  const { id: runId } = store.createRun({
    requestId: randomUUID(), projectId, goal: 'Exercise product-side paging.',
    sourceMode: 'public', capabilityTier: 2, budgetUsd: 5, budgetRequests: 5000,
    maxRpsPerOrigin: 50, workerConcurrency: 2, workerMaxTurns: 20,
  })
  return { dir, store, runId }
}

/** 6,000 declared operations: 3,000 literal paths, each declaring GET + POST. */
function declaredCatalog(paths: number): { doc: Record<string, unknown>; keys: Array<{ method: string; pathTemplate: string }> } {
  const doc: Record<string, unknown> = { openapi: '3.1.0', info: { title: 'paging', version: '1' }, paths: {} }
  const documentPaths = doc.paths as Record<string, unknown>
  const keys: Array<{ method: string; pathTemplate: string }> = []
  for (let i = 0; i < paths; i += 1) {
    const path = `/api/v7/things/item${i}`
    documentPaths[path] = { get: {}, post: {} }
    keys.push({ method: 'GET', pathTemplate: path }, { method: 'POST', pathTemplate: path })
  }
  return { doc, keys }
}

test('v6 declared-surface ingestion pages past 500 rows and dedupes exactly', t => {
  const { store, runId } = makeStore(t, 'declared-ingest')
  const run = store.run(runId)
  const { doc, keys } = declaredCatalog(3000)

  // Pre-existing declared rows far beyond one page: the dedupe baseline must see all 2,500.
  store.transaction(() => {
    for (let i = 0; i < 2500; i += 1) {
      store.upsertEndpoint({
        runId,
        origin: ORIGIN,
        method: 'GET',
        pathTemplate: `/api/v7/things/item${i}`,
        source: 'spa_crawl',
        riskScore: 10 + (i % 91),
      })
    }
  })
  assert.equal(store.listEndpoints(runId, { origin: ORIGIN }).length, 500,
    'unpaged read is the 500-row default the regression is about')
  assert.equal(listEndpointsPaged(store, runId, { origin: ORIGIN }).length, 2500,
    'paged read sees the whole pre-existing surface')

  store.importProjectSpec({
    requestId: randomUUID(),
    projectId: run.projectId,
    name: 'paging.json',
    kind: 'openapi',
    origin: ORIGIN,
    content: JSON.stringify(doc),
  })

  const first = ingestDeclaredApiSurface({
    storage: store,
    runId,
    scopeRevision: store.run(runId).scopeRevision,
    origin: ORIGIN,
  })
  assert.equal(first.specs, 1)
  assert.equal(first.declaredOpsSeen, 6000, 'every declared operation is enumerated')
  assert.equal(first.declaredOpsMatched, 6000, 'declaredOpsMatched == declaredOpsSeen (lossless)')
  assert.equal(first.declaredTolerantCapped, 0)
  assert.equal(first.endpoints, 3500, 'only the 3,500 genuinely new operations are counted')
  assert.equal(first.methods.GET, 500, 'pre-existing GET operations are not double-counted')
  assert.equal(first.methods.POST, 3000)
  assert.equal(listEndpointsPaged(store, runId, { origin: ORIGIN }).length, 6000,
    'store holds exactly one row per declared operation')

  const persistedKeys = new Set(listEndpointsPaged(store, runId, { origin: ORIGIN })
    .map(row => `${row.method.toUpperCase()} ${row.pathTemplate}`))
  for (const key of keys) assert.ok(persistedKeys.has(`${key.method} ${key.pathTemplate}`), `persisted ${key.method} ${key.pathTemplate}`)

  const second = ingestDeclaredApiSurface({
    storage: store,
    runId,
    scopeRevision: store.run(runId).scopeRevision,
    origin: ORIGIN,
  })
  assert.equal(second.endpoints, 0, 're-ingestion is idempotent')
  assert.equal(second.declaredOpsSeen, 6000)
  assert.equal(second.declaredOpsMatched, 6000)
  assert.equal(listEndpointsPaged(store, runId, { origin: ORIGIN }).length, 6000)
})

test('v6 malformed references keep the tolerant cap and report when it binds', t => {
  const { store, runId } = makeStore(t, 'tolerant-cap')
  const run = store.run(runId)
  const raw = JSON.stringify(declaredCatalog(250).doc).replace('"openapi"', '"\u0001openapi"')
  assert.throws(() => JSON.parse(raw), 'fixture must be invalid JSON')
  assert.equal(countTolerantOpenApiOperations(raw), 500, 'the malformed document declares 500 ops')
  assert.equal(harvestTolerantOpenApiOperations(raw).length, 300, 'tolerant scan is safety-capped')

  store.importProjectSpec({
    requestId: randomUUID(),
    projectId: run.projectId,
    name: 'truncated.json',
    kind: 'openapi',
    origin: ORIGIN,
    content: raw,
  })
  const result = ingestDeclaredApiSurface({
    storage: store,
    runId,
    scopeRevision: store.run(runId).scopeRevision,
    origin: ORIGIN,
  })
  assert.equal(result.declaredTolerantCapped, 1, 'capped tolerant scan is counted')
  assert.equal(result.declaredOpsSeen, 300)
  assert.equal(result.declaredOpsMatched, 300)
  const capped = store.eventsAfter(runId, 0, 2000).filter(event => event.kind === 'phase0.declared_surface_capped')
  assert.equal(capped.length, 1, 'cap binding is logged once for the malformed spec')
})

test('v6 probe selection considers all 6,000 rows before the intentional 220/150 cap', t => {
  const { store, runId } = makeStore(t, 'probe-selection')
  const total = 6000
  store.transaction(() => {
    for (let i = 0; i < total; i += 1) {
      store.upsertEndpoint({
        runId,
        origin: ORIGIN,
        method: i % 5 === 0 ? 'DELETE' : i % 3 === 0 ? 'POST' : 'GET',
        pathTemplate: `/api/v7/surface/route${i}`,
        source: 'spa_crawl',
        riskScore: i % 101,
      })
    }
  })

  const tailPath = '/api/v7/surface/tail-low'
  store.upsertEndpoint({
    runId, origin: ORIGIN, method: 'GET', pathTemplate: tailPath, source: 'spa_crawl', riskScore: 0,
  })

  const rows = listEndpointsPaged(store, runId, { orderBy: 'risk' })
  assert.equal(rows.length, total + 1, 'paged read is lossless')
  assert.equal(store.listEndpoints(runId, { orderBy: 'risk' }).length, 500,
    'a single unpaged read still truncates — selection must not depend on it')

  const everything = selectProbeCandidates({
    endpoints: rows,
    probePlan: null,
    cap: total + 1,
    approvedOrigins: new Set([ORIGIN]),
  })
  assert.equal(everything.considered, total + 1, 'every row is considered before any cap applies')
  assert.equal(everything.selected, total + 1, 'a larger cap can reach the last-ranked row')

  const engine = selectProbeCandidates({
    endpoints: rows,
    probePlan: null,
    cap: ENGINE_PROBE_CAP,
    approvedOrigins: new Set([ORIGIN]),
  })
  assert.equal(engine.considered, total + 1)
  assert.equal(engine.selected, ENGINE_PROBE_CAP)
  assert.equal(engine.cap, ENGINE_PROBE_CAP)
  assert.equal(engine.skippedStored, total + 1 - ENGINE_PROBE_CAP)
  assert.deepEqual(probeSelectionMetrics(engine), {
    probeCandidatesConsidered: total + 1,
    probeSelected: ENGINE_PROBE_CAP,
    probeCap: ENGINE_PROBE_CAP,
    storedRows: total + 1,
  })

  const deterministic = selectProbeCandidates({
    endpoints: rows,
    probePlan: null,
    cap: DETERMINISTIC_PROBE_CAP,
    approvedOrigins: new Set([ORIGIN]),
    excludeMethods: ['DELETE'],
  })
  const deleteRows = rows.filter(row => row.method === 'DELETE').length
  assert.equal(deterministic.considered, total + 1 - deleteRows, 'DELETE exclusion is applied to the full surface')
  assert.equal(deterministic.selected, DETERMINISTIC_PROBE_CAP)

  // A plan sample naming a route that ranks last must win: tail rows are now reachable.
  const plan = selectProbeCandidates({
    endpoints: rows,
    probePlan: { sample: [`GET ${tailPath}`] },
    cap: ENGINE_PROBE_CAP,
    approvedOrigins: new Set([ORIGIN]),
  })
  assert.equal(plan.usedPlan, true)
  assert.equal(`${plan.targets[0]!.method} ${plan.targets[0]!.pathTemplate}`, `GET ${tailPath}`)
  assert.equal(plan.selected, ENGINE_PROBE_CAP)

  const digest = (selection: { targets: Array<{ method: string; pathTemplate: string }> }) =>
    createHash('sha256')
      .update(selection.targets.map(row => `${row.method.toUpperCase()} ${row.pathTemplate}`).join('\n'))
      .digest('hex')
  assert.equal(digest(engine), digest(selectProbeCandidates({
    endpoints: [...rows].reverse(),
    probePlan: null,
    cap: ENGINE_PROBE_CAP,
    approvedOrigins: new Set([ORIGIN]),
  })), 'store arrival order does not change the selected set or rank order')

  // Two independently-built stores with the same surface (and so different row ids) agree.
  const other = makeStore(t, 'probe-selection-twin')
  other.store.transaction(() => {
    for (let i = total - 1; i >= 0; i -= 1) {
      other.store.upsertEndpoint({
        runId: other.runId,
        origin: ORIGIN,
        method: i % 5 === 0 ? 'DELETE' : i % 3 === 0 ? 'POST' : 'GET',
        pathTemplate: `/api/v7/surface/route${i}`,
        source: 'spa_crawl',
        riskScore: i % 101,
      })
    }
  })
  other.store.upsertEndpoint({
    runId: other.runId, origin: ORIGIN, method: 'GET', pathTemplate: tailPath, source: 'spa_crawl', riskScore: 0,
  })
  const twinRows = listEndpointsPaged(other.store, other.runId, { orderBy: 'risk' })
  assert.equal(twinRows.length, total + 1)
  assert.equal(digest(selectProbeCandidates({
    endpoints: twinRows,
    probePlan: null,
    cap: ENGINE_PROBE_CAP,
    approvedOrigins: new Set([ORIGIN]),
  })), digest(engine), 'selection is deterministic across stores')

  // Out-of-scope origins are filtered before ranking, not dropped after a cap.
  const scoped = selectProbeCandidates({
    endpoints: rows,
    probePlan: null,
    cap: ENGINE_PROBE_CAP,
    approvedOrigins: new Set(['https://other.example']),
  })
  assert.equal(scoped.considered, 0)
  assert.equal(scoped.selected, 0)
})
