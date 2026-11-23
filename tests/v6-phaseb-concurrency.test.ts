/**
 * Phase-B F1: separate benchmark *cell* concurrency from *in-run worker* concurrency.
 *
 * The harness used to pass `--concurrency` (parallel app/seed cells, default 1) into
 * `runs.worker_concurrency`, so an agentic cell ran 26 ready steps through a single worker slot.
 * These tests pin:
 *  - defaults (agentic 6, deterministic 1) and explicit `--worker-concurrency` overrides;
 *  - cell scheduling is unchanged by the worker flag;
 *  - cell meta records both values;
 *  - certify ingests both values and the corrected lead funnel (queued vs. investigated);
 *  - the det_lead funnel counts a verdict, not a queue event.
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  DEFAULT_AGENTIC_WORKER_CONCURRENCY,
  DEFAULT_NO_LLM_WORKER_CONCURRENCY,
  MAX_RUN_WORKER_CONCURRENCY,
  defaultWorkerConcurrency,
  resolveWorkerConcurrency,
} from '../scripts/benchmark-env.ts'
import {
  cellKeys,
  concurrencyMeta,
  parseRealisticArgs,
  runWorkerConcurrency,
  shouldIsolateDataDir,
  summarizeLeadFunnel,
} from '../scripts/benchmark-realistic.ts'
import { buildRunPlan, evaluateCertification, ingestFromDirs } from '../scripts/certify-phase1.ts'
import type { RealismRun } from '../scripts/certify-phase1.ts'

// ---------------------------------------------------------------------------------------------
// Parsing and defaults
// ---------------------------------------------------------------------------------------------

test('concurrency: agentic default is 6 workers, deterministic default is 1', () => {
  assert.equal(DEFAULT_AGENTIC_WORKER_CONCURRENCY, 6)
  assert.equal(DEFAULT_NO_LLM_WORKER_CONCURRENCY, 1)
  assert.equal(defaultWorkerConcurrency(false), 6)
  assert.equal(defaultWorkerConcurrency(true), 1)

  const agentic = parseRealisticArgs([], {})
  assert.equal(agentic.concurrency, 1, 'cell concurrency keeps its historical default')
  assert.equal(agentic.workerConcurrency, 6)

  const deterministic = parseRealisticArgs(['--no-llm'], {})
  assert.equal(deterministic.concurrency, 1)
  assert.equal(deterministic.workerConcurrency, 1)
})

test('concurrency: cell --concurrency never sets the in-run worker count', () => {
  const parallel = parseRealisticArgs(['--concurrency', '3'], {})
  assert.equal(parallel.concurrency, 3)
  assert.equal(parallel.workerConcurrency, 6, 'three cells x one worker each is the old bug')

  const parallelFloor = parseRealisticArgs(['--concurrency', '4', '--no-llm'], {})
  assert.equal(parallelFloor.concurrency, 4)
  assert.equal(parallelFloor.workerConcurrency, 1)
})

test('concurrency: explicit --worker-concurrency overrides both modes', () => {
  const agentic = parseRealisticArgs(['--worker-concurrency', '4'], {})
  assert.equal(agentic.workerConcurrency, 4)
  assert.equal(agentic.concurrency, 1)

  const deterministic = parseRealisticArgs(['--no-llm', '--worker-concurrency', '3'], {})
  assert.equal(deterministic.workerConcurrency, 3)

  const single = parseRealisticArgs(['--worker-concurrency', '1'], {})
  assert.equal(single.workerConcurrency, 1, 'an explicit 1 is preserved for control runs')
})

test('concurrency: --worker-concurrency is bounded by the engine ceiling', () => {
  assert.throws(() => parseRealisticArgs(['--worker-concurrency', '0'], {}), /--worker-concurrency/)
  assert.throws(() => parseRealisticArgs(['--worker-concurrency', '-2'], {}), /--worker-concurrency/)
  assert.throws(() => parseRealisticArgs(['--worker-concurrency', '1.5'], {}), /--worker-concurrency/)
  assert.throws(
    () => parseRealisticArgs(['--worker-concurrency', String(MAX_RUN_WORKER_CONCURRENCY + 1)], {}),
    new RegExp(`between 1 and ${MAX_RUN_WORKER_CONCURRENCY}`),
  )
  assert.equal(
    parseRealisticArgs(['--worker-concurrency', String(MAX_RUN_WORKER_CONCURRENCY)], {}).workerConcurrency,
    MAX_RUN_WORKER_CONCURRENCY,
  )
})

test('concurrency: resolveWorkerConcurrency clamps without ever returning 0', () => {
  assert.equal(resolveWorkerConcurrency(undefined), 6)
  assert.equal(resolveWorkerConcurrency(undefined, { noLlm: true }), 1)
  assert.equal(resolveWorkerConcurrency(0), 1)
  assert.equal(resolveWorkerConcurrency(99), MAX_RUN_WORKER_CONCURRENCY)
  assert.equal(resolveWorkerConcurrency(4.9), 4)
  assert.equal(runWorkerConcurrency({ workerConcurrency: 5, noLlm: false }), 5)
})

// ---------------------------------------------------------------------------------------------
// Cell scheduling is untouched
// ---------------------------------------------------------------------------------------------

test('concurrency: worker slots do not change cell keys, cell parallelism or isolation', () => {
  const base = parseRealisticArgs(['--app', 'all', '--seeds', '1,2'], {})
  const workers = parseRealisticArgs(['--app', 'all', '--seeds', '1,2', '--worker-concurrency', '8'], {})
  assert.deepEqual(cellKeys(base), cellKeys(workers))
  assert.equal(cellKeys(workers).length, 6)
  assert.equal(base.concurrency, workers.concurrency)
  assert.equal(workers.concurrency, 1)

  // Data-dir isolation follows cell concurrency, not worker concurrency.
  assert.equal(shouldIsolateDataDir({ ...base, dataDir: '/tmp/data', concurrency: 1 }), false)
  assert.equal(shouldIsolateDataDir({ ...base, dataDir: '/tmp/data', concurrency: 2 }), true)
  assert.equal(shouldIsolateDataDir({ ...workers, dataDir: '/tmp/data', concurrency: 1 }), false)
})

test('concurrency: cell meta records both values independently', () => {
  const args = parseRealisticArgs(['--concurrency', '2', '--worker-concurrency', '6'], {})
  const meta = concurrencyMeta(args)
  assert.deepEqual(meta, { cellConcurrency: 2, workerConcurrency: 6 })

  const floor = concurrencyMeta(parseRealisticArgs(['--concurrency', '4', '--no-llm'], {}))
  assert.deepEqual(floor, { cellConcurrency: 4, workerConcurrency: 1 })
})

// ---------------------------------------------------------------------------------------------
// Corrected det_lead funnel
// ---------------------------------------------------------------------------------------------

test('lead funnel: investigated counts verdicts, not queue events', () => {
  const funnel = summarizeLeadFunnel({
    events: [
      { kind: 'deterministic_engine.lead', detail: { probeClass: 'authz_matrix' } },
      { kind: 'deterministic_engine.lead', detail: { probeClass: 'authz_matrix' } },
      { kind: 'deterministic_lane.lead_consumed', detail: { factId: 'fact-a', stepId: 'step-a' } },
      { kind: 'deterministic_lane.lead_consumed', detail: { factId: 'fact-b', stepId: 'step-b' } },
    ],
    assignments: [
      { stepId: 'step-a', status: 'complete' },
      // Killed assignment: dispatched but no verdict, so it must not count as investigated.
      { stepId: 'step-b', status: 'canceled' },
    ],
  })
  assert.deepEqual(funnel, {
    emitted: 2,
    queued: 2,
    dispatched: 2,
    investigated: 1,
    source: 'events',
  })
})

test('lead funnel: queued-but-never-dispatched leads report zero investigation', () => {
  const funnel = summarizeLeadFunnel({
    events: [
      { kind: 'deterministic_engine.lead', detail: {} },
      { kind: 'deterministic_lane.lead_consumed', detail: { factId: 'fact-only', stepId: 'step-ready' } },
    ],
    assignments: [],
  })
  assert.equal(funnel.emitted, 1)
  assert.equal(funnel.queued, 1)
  assert.equal(funnel.dispatched, 0)
  assert.equal(funnel.investigated, 0, 'a queued lead is not evidence of work')
})

test('lead funnel: repeated queue events for one fact are counted once', () => {
  const funnel = summarizeLeadFunnel({
    events: [
      { kind: 'deterministic_lane.lead_consumed', detail: { factId: 'fact-a', stepId: 'step-a' } },
      { kind: 'deterministic_lane.lead_consumed', detail: { factId: 'fact-a', stepId: 'step-a' } },
    ],
    assignments: [{ stepId: 'step-a', status: 'complete' }],
  })
  assert.equal(funnel.queued, 1)
  assert.equal(funnel.investigated, 1)
})

test('lead funnel: a re-queued multi-trial upgrade step still counts its verdict', () => {
  const funnel = summarizeLeadFunnel({
    events: [
      { kind: 'deterministic_lane.lead_consumed', detail: { factId: 'fact-invoice', stepId: 'step-original' } },
    ],
    assignments: [
      { stepId: 'step-original', status: 'canceled' },
      { stepId: 'step-trial2', status: 'complete' },
    ],
    steps: [
      { id: 'step-original', title: 'det_lead upgrade · authz_matrix DELETE /api/invoices', dependsOnFactIds: ['fact-invoice'] },
      { id: 'step-trial2', title: 'det_lead upgrade · authz_matrix DELETE /api/invoices [trial 2]', dependsOnFactIds: ['fact-invoice'] },
    ],
  })
  assert.equal(funnel.queued, 1)
  assert.equal(funnel.dispatched, 1)
  assert.equal(funnel.investigated, 1, 'the completed trial is the verdict for the same lead fact')
})

test('lead funnel: broad planner steps bound to a lead fact do not fake a verdict', () => {
  const funnel = summarizeLeadFunnel({
    events: [
      { kind: 'deterministic_lane.lead_consumed', detail: { factId: 'fact-invoice', stepId: 'step-original' } },
    ],
    assignments: [{ stepId: 'step-broad', status: 'complete' }],
    steps: [
      { id: 'step-original', title: 'det_lead upgrade · authz_matrix DELETE /api/invoices', dependsOnFactIds: ['fact-invoice'] },
      { id: 'step-broad', title: 'Cross-persona BOLA matrix', dependsOnFactIds: ['fact-invoice'] },
    ],
  })
  assert.equal(funnel.investigated, 0)
})

// ---------------------------------------------------------------------------------------------
// Certify ingestion + run-plan plumbing
// ---------------------------------------------------------------------------------------------

function writeCellFixture(root: string, overrides: {
  confirmed?: number
  workerConcurrency?: number
  cellConcurrency?: number
  leadFunnel?: Record<string, number>
} = {}): string {
  mkdirSync(root, { recursive: true })
  const card = {
    app: 'acme-saas',
    seed: 1,
    seedSet: 'dev',
    mode: 'grey-box',
    targets: 22,
    confirmed: overrides.confirmed ?? 11,
    recall: (overrides.confirmed ?? 11) / 22,
    precision: 1,
    strictPrecision: 1,
    decoyFalsePositives: 0,
    unmatchedFalsePositives: 0,
    vulns: Array.from({ length: 22 }, (_, index) => ({
      siteId: `acme-saas-site-${String(index).padStart(2, '0')}`,
      vulnClass: 'bola',
      outcome: index < (overrides.confirmed ?? 11) ? 'confirmed' : 'missed',
    })),
  }
  writeFileSync(join(root, 'summary.json'), `${JSON.stringify([card], null, 2)}\n`)
  writeFileSync(join(root, 'acme-saas-seed1-grey-box.meta.json'), `${JSON.stringify({
    app: 'acme-saas',
    seed: 1,
    seedSet: 'dev',
    mode: 'grey-box',
    llm: 'agentic',
    model: { mode: 'agentic' },
    cellConcurrency: overrides.cellConcurrency ?? 1,
    workerConcurrency: overrides.workerConcurrency ?? 6,
    leadFunnel: overrides.leadFunnel ?? { emitted: 4, queued: 4, dispatched: 2, investigated: 0 },
  }, null, 2)}\n`)
  return root
}

function withFixture<T>(run: (root: string) => T, overrides: Parameters<typeof writeCellFixture>[1] = {}): T {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-phaseb-concurrency-'))
  try {
    return run(writeCellFixture(dir, overrides))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

test('certify: cell meta cellConcurrency and workerConcurrency are ingested separately', () => {
  withFixture(root => {
    const ingested = ingestFromDirs([root], {})
    assert.equal(ingested.runs.length, 1)
    const run = ingested.runs[0]!
    assert.equal(run.cellConcurrency, 4)
    assert.equal(run.workerConcurrency, 3)
  }, { cellConcurrency: 4, workerConcurrency: 3 })
})

test('certify: lead funnel maps queued vs investigated and keeps consumed=investigated', () => {
  withFixture(root => {
    const run = ingestFromDirs([root], {}).runs[0]!
    assert.equal(run.floor.floorLeadsEmitted, 4)
    assert.equal(run.floor.floorLeadsQueued, 4)
    assert.equal(run.floor.floorLeadsInvestigated, 0)
    assert.equal(run.floor.floorLeadsConsumed, 0, 'four queued leads with no verdict is not consumption')
  })
  withFixture(root => {
    const run = ingestFromDirs([root], {}).runs[0]!
    assert.equal(run.floor.floorLeadsQueued, 4)
    assert.equal(run.floor.floorLeadsInvestigated, 3)
    assert.equal(run.floor.floorLeadsConsumed, 3)
    assert.equal(run.floor.floorLeadsEmitted, 4)
  }, { leadFunnel: { emitted: 4, queued: 4, dispatched: 4, investigated: 3 } })
})

test('certify: certificate reports worker concurrency and flags single-slot agentic runs', () => {
  const certify = (workerConcurrency: number) => withFixture(root => {
    const ingested = ingestFromDirs([root], {})
    return evaluateCertification(ingested.runs, [], { mode: 'from-dir', apps: ['acme-saas'], notes: [] })
  }, { workerConcurrency })

  const healthy = certify(6)
  assert.equal(healthy.concurrency.worker.dev, 6)
  assert.deepEqual(healthy.concurrency.singleWorkerRuns, [])
  const workerMetric = healthy.informational.find(metric => metric.id === 'agentic_worker_concurrency')
  assert.equal(workerMetric?.status, 'MEETS')

  const starved = certify(1)
  assert.equal(starved.concurrency.worker.dev, 1)
  assert.equal(starved.concurrency.singleWorkerRuns.length, 1)
  assert.equal(
    starved.informational.find(metric => metric.id === 'agentic_worker_concurrency')?.status,
    'BELOW',
  )
})

test('certify: run plan forwards --worker-concurrency to agentic cells only', () => {
  const plan = buildRunPlan({
    outDir: '/tmp/phaseb-plan',
    apps: ['acme-saas'],
    devSeed: 1,
    heldoutSeed: 1_000_042,
    devRuns: 1,
    floorHeldoutRuns: 1,
    heldoutRuns: 1,
    dataDir: '/tmp/data',
    verifier: 'docker',
    budgetUsd: 2,
    maxDurationMs: 600_000,
    reasonRuns: 0,
    mode: 'grey-box',
    workerConcurrency: 6,
  })
  const hasWorkerFlag = (id: string) => {
    const cell = plan.find(entry => entry.id.startsWith(id))
    assert.ok(cell, `missing plan cell ${id}`)
    const index = cell.args.indexOf('--worker-concurrency')
    return index >= 0 ? cell.args[index + 1] : null
  }
  assert.equal(hasWorkerFlag('floor-dev-'), null, 'floor cells stay deterministic/sequential')
  assert.equal(hasWorkerFlag('floor-heldout-'), null)
  assert.equal(hasWorkerFlag('unified-dev-'), '6')
  assert.equal(hasWorkerFlag('unified-heldout-'), '6')

  const defaults = buildRunPlan({
    outDir: '/tmp/phaseb-plan-default',
    apps: ['acme-saas'],
    devSeed: 1,
    heldoutSeed: 1_000_042,
    devRuns: 1,
    floorHeldoutRuns: 1,
    heldoutRuns: 1,
    dataDir: '/tmp/data',
    verifier: 'docker',
    budgetUsd: 2,
    maxDurationMs: 600_000,
    reasonRuns: 0,
    mode: 'grey-box',
  })
  const unified = defaults.find(entry => entry.id.startsWith('unified-dev-'))!
  assert.equal(unified.args.includes('--worker-concurrency'), false, 'absent means harness default 6')
})

// Keep the type import used even if the fixture shape evolves.
const _realismRun: RealismRun['workerConcurrency'] = 6
void _realismRun
