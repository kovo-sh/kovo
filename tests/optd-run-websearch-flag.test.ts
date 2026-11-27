import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { newRun } from '../src/domain.ts'
import { STORE_SCHEMA_VERSION, Store } from '../src/server/store.ts'
import {
  acquireBenchModeEnv,
  buildMultihopCellEnv,
} from '../scripts/benchmark-multihop.ts'
import { resolveObservedEffectiveConfigForRunner } from '../scripts/benchmark-realistic.ts'

function tempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix))
}

function createLabProject(store: Store): string {
  const project = store.createProject({
    requestId: randomUUID(),
    name: 'WebSearch Flag Project',
    seeds: ['https://example.test'],
    environment: 'public',
  })
  return project.id
}

test('default createRun and newRun Zod schema set allowWebSearch === true', t => {
  const dir = tempDir('kovo-optd-websearch-default-')
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const store = new Store(dir)
  t.after(() => { try { store.close() } catch { /* already closed */ } })
  const projectId = createLabProject(store)

  // (a1) Zod schema defaults allowWebSearch to true when omitted (product API default).
  const parsed = newRun.parse({
    requestId: randomUUID(),
    projectId,
    goal: 'Default product scan should allow web search.',
  })
  assert.equal(parsed.allowWebSearch, true)

  const { id: runIdFromSchema } = store.createRun(parsed)
  assert.equal(store.run(runIdFromSchema).allowWebSearch, true)

  // (a2) Direct Store.createRun omitting allowWebSearch defaults to true.
  const { id: runIdDirect } = store.createRun({
    requestId: randomUUID(),
    projectId,
    goal: 'Direct store createRun omitting allowWebSearch.',
    sourceMode: 'public',
    capabilityTier: 1,
    budgetUsd: 5,
    budgetRequests: 200,
    maxRpsPerOrigin: 5,
    workerConcurrency: 2,
    workerMaxTurns: 20,
  })
  assert.equal(store.run(runIdDirect).allowWebSearch, true)

  const listed = store.projectDetail(projectId).runs
  const byId = new Map(listed.map(r => [r.id, r]))
  assert.equal(byId.get(runIdFromSchema)?.allowWebSearch, true)
  assert.equal(byId.get(runIdDirect)?.allowWebSearch, true)
})

test('explicit allowWebSearch: false persists to SQLite and hydrates as false across reopen', t => {
  const dir = tempDir('kovo-optd-websearch-false-')
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  let projectId = ''
  let runId = ''
  {
    const store = new Store(dir)
    try {
      projectId = createLabProject(store)
      const parsed = newRun.parse({
        requestId: randomUUID(),
        projectId,
        goal: 'Operator disabled web search for this run.',
        allowWebSearch: false,
      })
      assert.equal(parsed.allowWebSearch, false)

      const created = store.createRun(parsed)
      runId = created.id
      assert.equal(store.run(runId).allowWebSearch, false)

      const raw = store.client.prepare('SELECT allow_web_search FROM runs WHERE id = ?').get(runId) as {
        allow_web_search: number
      }
      assert.equal(raw.allow_web_search, 0)

      const listed = store.projectDetail(projectId).runs.find(r => r.id === runId)
      assert.equal(listed?.allowWebSearch, false)
    } finally {
      store.close()
    }
  }

  // Reopen Store from disk to verify persistence & hydration.
  const reopened = new Store(dir)
  t.after(() => { try { reopened.close() } catch { /* already closed */ } })
  assert.equal(reopened.run(runId).allowWebSearch, false)
  const listedAfter = reopened.projectDetail(projectId).runs.find(r => r.id === runId)
  assert.equal(listedAfter?.allowWebSearch, false)
})

test('existing SQLite DB without allow_web_search column migrates cleanly with default true', t => {
  const dir = tempDir('kovo-optd-websearch-migrate-')
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  let projectId = ''
  let legacyRunId = ''
  {
    const store = new Store(dir)
    try {
      projectId = createLabProject(store)
      const created = store.createRun(newRun.parse({
        requestId: randomUUID(),
        projectId,
        goal: 'Pre-v13 legacy run row.',
      }))
      legacyRunId = created.id
    } finally {
      store.close()
    }
  }

  // Simulate an existing v12 SQLite DB lacking the runs.allow_web_search column.
  const rawDb = new DatabaseSync(join(dir, 'kovo.sqlite'))
  try {
    rawDb.exec('ALTER TABLE runs DROP COLUMN allow_web_search;')
    rawDb.exec('PRAGMA user_version = 12;')
    const v12Cols = new Set(
      (rawDb.prepare('PRAGMA table_info(runs)').all() as Array<{ name: string }>).map(c => c.name),
    )
    assert.equal(v12Cols.has('allow_web_search'), false, 'simulated v12 DB must lack allow_web_search')
  } finally {
    rawDb.close()
  }

  // Reopen with Store: migration v13 adds allow_web_search INTEGER NOT NULL DEFAULT 1 idempotently.
  const migrated = new Store(dir)
  t.after(() => { try { migrated.close() } catch { /* already closed */ } })
  assert.equal(migrated.migrationReport.fromVersion, 12)
  assert.equal(migrated.migrationReport.toVersion, STORE_SCHEMA_VERSION)
  assert.equal(STORE_SCHEMA_VERSION, 13)
  Store.verifySchema(migrated.client)

  const cols = new Set(
    (migrated.client.prepare('PRAGMA table_info(runs)').all() as Array<{ name: string }>).map(c => c.name),
  )
  assert.equal(cols.has('allow_web_search'), true)
  assert.equal(migrated.run(legacyRunId).allowWebSearch, true)

  // Reopening a second time is idempotent and applies 0 migrations.
  migrated.close()
  const reopened = new Store(dir)
  t.after(() => { try { reopened.close() } catch { /* already closed */ } })
  assert.equal(reopened.migrationReport.applied.length, 0)
  assert.equal(reopened.run(legacyRunId).allowWebSearch, true)
})

test('benchmark-multihop cell env forces KOVO_BENCH_MODE=1 and tracks KOVO_DECOUPLED_PROOF_PIPELINE in effectiveConfigHash', () => {
  const prevBench = process.env.KOVO_BENCH_MODE
  const release = acquireBenchModeEnv()
  try {
    assert.equal(process.env.KOVO_BENCH_MODE, '1')
  } finally {
    release()
    assert.equal(process.env.KOVO_BENCH_MODE, prevBench)
  }

  const baseObserved = {
    environment: 'local-lab',
    environmentMode: 'ephemeral_lab',
    tier: 3,
    approvalPolicy: 'auto_review',
    deterministicOnly: false,
    wordlistOn: false,
    proofReceiptMode: 'strict',
  }

  const envBaseline = buildMultihopCellEnv({})
  const envDecoupled = buildMultihopCellEnv({ KOVO_DECOUPLED_PROOF_PIPELINE: '1' })

  assert.equal(envBaseline.KOVO_BENCH_MODE, '1')
  assert.equal(envBaseline.KOVO_DECOUPLED_PROOF_PIPELINE, undefined)
  assert.equal(envDecoupled.KOVO_BENCH_MODE, '1')
  assert.equal(envDecoupled.KOVO_DECOUPLED_PROOF_PIPELINE, '1')

  const cfgBaseline = resolveObservedEffectiveConfigForRunner({
    observed: baseObserved,
    deterministicOnly: false,
    environment: 'local-lab',
    approvalPolicy: 'auto_review',
    verifierBackend: 'docker',
    mode: 'grey-box',
    env: envBaseline,
    extra: { allowWebSearch: false },
  })
  const cfgDecoupled = resolveObservedEffectiveConfigForRunner({
    observed: baseObserved,
    deterministicOnly: false,
    environment: 'local-lab',
    approvalPolicy: 'auto_review',
    verifierBackend: 'docker',
    mode: 'grey-box',
    env: envDecoupled,
    extra: { allowWebSearch: false, decoupledProofPipeline: '1' },
  })

  assert.equal(cfgBaseline.observed, true)
  assert.equal(cfgDecoupled.observed, true)
  assert.equal(cfgBaseline.effectiveConfig?.kovoEnv.KOVO_BENCH_MODE, '1')
  assert.equal(cfgDecoupled.effectiveConfig?.kovoEnv.KOVO_BENCH_MODE, '1')
  assert.equal(cfgDecoupled.effectiveConfig?.kovoEnv.KOVO_DECOUPLED_PROOF_PIPELINE, '1')
  assert.equal(cfgBaseline.effectiveConfig?.extra?.allowWebSearch, false)
  assert.notEqual(
    cfgBaseline.effectiveConfigHash,
    cfgDecoupled.effectiveConfigHash,
    'effectiveConfigHash must distinguish KOVO_DECOUPLED_PROOF_PIPELINE=1 A/B runs',
  )
})
