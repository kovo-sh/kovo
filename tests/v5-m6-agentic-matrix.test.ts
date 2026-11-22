/**
 * v5 M6: agentic benchmark matrix — CLI parsing, cell planning/scheduling, structured
 * scorecard collection and fail-closed classification. No real benchmark cells run here.
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { after, describe, test } from 'node:test'

import {
  DEFAULT_MATRIX_BUDGET_USD, DEFAULT_MATRIX_CONCURRENCY, DEFAULT_MATRIX_MAX_DURATION_MS,
  SMOKE_BUDGET_USD, SMOKE_MAX_DURATION_MS, buildCells, cellArtifactPaths, cellChildArgs,
  collectCellResult, main, matrixExitCode, parseMatrixArgs, renderMatrixSummary, renderMatrixTable,
  runMatrix, summarizeMatrix,
} from '../scripts/benchmark-agentic-matrix.ts'
import type { MatrixArgs, MatrixCell, MatrixCellResult } from '../scripts/benchmark-agentic-matrix.ts'

const SALT_ENV = { GUARDIAN_RB_HELDOUT_SALT: 'a'.repeat(48) }

function matrixArgs(over: Partial<MatrixArgs> = {}): MatrixArgs {
  return {
    apps: ['acme-saas'],
    seeds: [1],
    modes: ['grey-box'],
    budgetUsd: 5,
    maxDurationMs: DEFAULT_MATRIX_MAX_DURATION_MS,
    concurrency: 1,
    outDir: '/tmp/agentic-matrix-test',
    dataDir: '/tmp/guardian-data',
    noLlm: false,
    verifier: 'docker',
    keepDataDirs: false,
    smoke: false,
    childTimeoutMs: 1_200_000,
    help: false,
    ...over,
  }
}

function cell(over: Partial<MatrixCell> = {}): MatrixCell {
  const base: MatrixCell = {
    app: 'acme-saas', seed: 1, mode: 'grey-box', seedSet: 'dev',
    label: 'acme-saas-seed1-grey-box',
  }
  return { ...base, ...over }
}

const tempDirs: string[] = []
function tempDir(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `guardian-matrix-${label}-`))
  tempDirs.push(dir)
  return dir
}
after(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true })
})

function writeArtifacts(
  args: Pick<MatrixArgs, 'outDir'>,
  target: MatrixCell,
  scorecard: Record<string, unknown> | null,
  meta: Record<string, unknown> | null,
): void {
  const paths = cellArtifactPaths(args.outDir, target)
  mkdirSync(paths.dir, { recursive: true })
  if (scorecard) writeFileSync(paths.jsonPath, JSON.stringify(scorecard))
  if (meta) writeFileSync(paths.metaPath, JSON.stringify(meta))
}

const goodScorecard = {
  confirmed: 2, targets: 22, precision: 0.667, decoyFalsePositives: 0, decoys: 6,
  unmatchedFalsePositives: 1, totalCostUsd: 0.47,
  funnel: {
    targetVulns: 22, surfaceDiscovered: 20, hypothesisFormed: 9,
    signalObserved: 5, specSubmitted: 3, zeroLlmConfirmed: 0,
  },
  failureBuckets: { surface_miss: 2, signal_absent: 1 },
}

const goodMeta = {
  model: { mode: 'agentic', profiles: [{ name: 'p', model: 'deepseek/deepseek-v4.1-flash-1017', protocol: 'responses' }] },
  workerSessions: true,
  verifierBackend: 'docker',
  inert: false,
  endpointsDiscovered: 59,
  facts: 65,
  assignments: {
    total: 9, completed: 6, failed: 3, canceled: 0,
    investigationTotal: 6, investigationCompleted: 4, investigationFailed: 2,
  },
  durationMs: 120_000,
  timedOut: false,
  terminalStatus: 'complete',
}

describe('CLI parsing', () => {
  test('defaults are agentic-docker, three apps, dev seed 1, grey-box', () => {
    const args = parseMatrixArgs([], {})
    assert.deepEqual(args.apps, ['acme-saas', 'shopflow', 'opsportal'])
    assert.deepEqual(args.seeds, [1])
    assert.deepEqual(args.modes, ['grey-box'])
    assert.equal(args.budgetUsd, DEFAULT_MATRIX_BUDGET_USD)
    assert.equal(args.maxDurationMs, DEFAULT_MATRIX_MAX_DURATION_MS)
    assert.equal(args.concurrency, DEFAULT_MATRIX_CONCURRENCY)
    assert.equal(args.verifier, 'docker')
    assert.equal(args.noLlm, false)
    assert.equal(args.smoke, false)
    assert.equal(args.dataDir, undefined)
    assert.match(args.outDir, /\.guardian\/agentic-matrix$/)
    assert.equal(args.childTimeoutMs, DEFAULT_MATRIX_MAX_DURATION_MS + 5 * 60_000)
  })

  test('app/seed/mode/budget/duration/concurrency/out-dir/data-dir parse and dedupe', () => {
    const args = parseMatrixArgs([
      '--apps', 'opsportal,acme-saas,opsportal', '--seeds', '2,1,2',
      '--modes', 'white-box,grey-box', '--budget-usd', '2.5',
      '--max-duration-ms', '60000', '--concurrency', '2', '--out-dir', '/tmp/matrix',
      '--data-dir', '/tmp/guardian-data', '--verifier', 'local-jq',
      '--no-llm', '--keep-data-dirs', '--timeout-ms', '90000',
    ], {})
    assert.deepEqual(args.apps, ['opsportal', 'acme-saas'])
    assert.deepEqual(args.seeds, [2, 1])
    assert.deepEqual(args.modes, ['white-box', 'grey-box'])
    assert.equal(args.budgetUsd, 2.5)
    assert.equal(args.maxDurationMs, 60_000)
    assert.equal(args.concurrency, 2)
    assert.equal(resolve(args.outDir), resolve('/tmp/matrix'))
    assert.equal(resolve(args.dataDir!), resolve('/tmp/guardian-data'))
    assert.equal(args.verifier, 'local-jq')
    assert.equal(args.noLlm, true)
    assert.equal(args.keepDataDirs, true)
    assert.equal(args.childTimeoutMs, 90_000)
  })

  test('--apps all expands to every app; GUARDIAN_DATA_DIR is the default data dir', () => {
    const args = parseMatrixArgs(['--apps', 'all'], { GUARDIAN_DATA_DIR: '/tmp/gd' })
    assert.deepEqual(args.apps, ['acme-saas', 'shopflow', 'opsportal'])
    assert.equal(resolve(args.dataDir!), resolve('/tmp/gd'))
  })

  test('--smoke is the CI preset (90 s, $0.25) and explicit flags still win', () => {
    const smoke = parseMatrixArgs(['--smoke'], {})
    assert.equal(smoke.smoke, true)
    assert.equal(smoke.budgetUsd, SMOKE_BUDGET_USD)
    assert.equal(smoke.maxDurationMs, SMOKE_MAX_DURATION_MS)
    assert.equal(smoke.childTimeoutMs, SMOKE_MAX_DURATION_MS + 5 * 60_000)
    const overridden = parseMatrixArgs(['--smoke', '--budget-usd', '1', '--max-duration-ms', '30000'], {})
    assert.equal(overridden.budgetUsd, 1)
    assert.equal(overridden.maxDurationMs, 30_000)
  })

  test('held-out seeds require the salt env and are marked held-out', () => {
    assert.throws(() => parseMatrixArgs(['--seeds', '1000042'], {}), /GUARDIAN_RB_HELDOUT_SALT/)
    const args = parseMatrixArgs(['--apps', 'acme-saas', '--seeds', '1,1000042'], SALT_ENV)
    assert.deepEqual(buildCells(args).map(c => [c.seed, c.seedSet]), [[1, 'dev'], [1000042, 'held-out']])
    assert.equal(args.seeds.length, 2)
  })

  test('rejects unknown flags, missing values, bad modes/verifiers and out-of-range numbers', () => {
    assert.throws(() => parseMatrixArgs(['--nope'], {}), /unknown flag --nope/)
    assert.throws(() => parseMatrixArgs(['--apps'], {}), /--apps requires a value/)
    assert.throws(() => parseMatrixArgs(['--modes', 'purple-box'], {}), /--modes must be one of/)
    assert.throws(() => parseMatrixArgs(['--verifier', 'magic'], {}), /--verifier must be one of/)
    assert.throws(() => parseMatrixArgs(['--seeds', '0'], {}), /positive integer/)
    assert.throws(() => parseMatrixArgs(['--concurrency', '0'], {}), /positive integer/)
    assert.throws(() => parseMatrixArgs(['--budget-usd', '0'], {}), /--budget-usd must be a number/)
    assert.throws(() => parseMatrixArgs(['--timeout-ms', 'abc'], {}), /positive integer/)
    assert.throws(() => parseMatrixArgs(['stray'], {}), /unexpected argument/)
  })

  test('main refuses an agentic matrix without a model data dir', async () => {
    const code = await main(['--apps', 'acme-saas', '--out-dir', tempDir('nodata')])
    assert.equal(code, 2)
  })
})

describe('cell planning', () => {
  test('buildCells orders app -> seed -> mode and labels cells like scorecard artifacts', () => {
    const args = matrixArgs({
      apps: ['shopflow', 'acme-saas'], seeds: [1, 1000042], modes: ['grey-box', 'white-box'],
    })
    const cells = buildCells(args)
    assert.deepEqual(cells.map(c => c.label), [
      'shopflow-seed1-grey-box', 'shopflow-seed1-white-box',
      'shopflow-seed1000042-grey-box', 'shopflow-seed1000042-white-box',
      'acme-saas-seed1-grey-box', 'acme-saas-seed1-white-box',
      'acme-saas-seed1000042-grey-box', 'acme-saas-seed1000042-white-box',
    ])
    assert.equal(cells[2]!.seedSet, 'held-out')
    assert.equal(cellArtifactPaths('/out', cells[0]!).jsonPath, resolve('/out/shopflow-seed1-grey-box/shopflow-seed1-grey-box.json'))
  })

  test('child args isolate the data dir for agentic cells and pass --held-out', () => {
    const args = matrixArgs({ outDir: '/out', dataDir: '/data', verifier: 'docker' })
    const dev = cellChildArgs(cell(), args)
    assert.ok(dev.includes('--data-dir'))
    assert.equal(dev[dev.indexOf('--data-dir') + 1], '/data')
    assert.ok(dev.includes('--isolate-data-dir'))
    assert.equal(dev[dev.indexOf('--verifier') + 1], 'docker')
    assert.ok(!dev.includes('--held-out'))
    const heldout = cellChildArgs(cell({ seed: 1000042, seedSet: 'held-out', label: 'acme-saas-seed1000042-grey-box' }), args)
    assert.ok(heldout.includes('--held-out'))
    assert.ok(heldout.includes('--budget-usd'))
  })

  test('--no-llm cells never inherit the model data dir', () => {
    const args = matrixArgs({ outDir: '/out', dataDir: '/data', noLlm: true })
    const childArgs = cellChildArgs(cell(), args)
    assert.ok(childArgs.includes('--no-llm'))
    assert.ok(!childArgs.includes('--data-dir'))
    assert.ok(!childArgs.includes('--isolate-data-dir'))
    // Deterministic cells do not need Docker worker sessions unless asked explicitly.
    assert.equal(parseMatrixArgs(['--no-llm'], {}).verifier, 'auto')
    assert.equal(parseMatrixArgs(['--no-llm', '--verifier', 'docker'], {}).verifier, 'docker')
  })
})

describe('matrix scheduling', () => {
  test('runs every cell with bounded concurrency and returns sorted results', async () => {
    const args = matrixArgs({
      apps: ['acme-saas', 'shopflow'], seeds: [1, 2], concurrency: 2,
      outDir: tempDir('schedule'),
    })
    let active = 0
    let peak = 0
    const seen: string[] = []
    const results = await runMatrix(args, async (target) => {
      active += 1
      peak = Math.max(peak, active)
      seen.push(target.label)
      await new Promise(r => setTimeout(r, 10))
      active -= 1
      return { exitCode: 1, runtimeMs: 10, output: 'error: synthetic failure' }
    })
    assert.equal(seen.length, 4)
    assert.equal(new Set(seen).size, 4)
    assert.ok(peak <= 2, `peak concurrency ${peak} exceeded 2`)
    assert.deepEqual(results.map(r => r.label), [
      'acme-saas-seed1-grey-box', 'acme-saas-seed2-grey-box',
      'shopflow-seed1-grey-box', 'shopflow-seed2-grey-box',
    ])
    assert.ok(results.every(r => !r.ok && r.exitCode === 1))
  })

  test('executor exceptions become failed cells, not a rejected matrix', async () => {
    const args = matrixArgs({ outDir: tempDir('throws') })
    const results = await runMatrix(args, async () => { throw new Error('spawn EACCES') })
    assert.equal(results.length, 1)
    assert.equal(results[0]!.ok, false)
    assert.match(results[0]!.error ?? '', /spawn EACCES/)
    assert.equal(matrixExitCode(results), 1)
  })
})

describe('structured collection and fail-closed classification', () => {
  test('agentic cell maps scorecard + meta and is clean', () => {
    const args = { outDir: tempDir('good'), noLlm: false }
    const target = cell()
    writeArtifacts(args, target, goodScorecard, goodMeta)
    const result = collectCellResult(target, args, { exitCode: 0, runtimeMs: 121_000, output: '' })
    assert.equal(result.ok, true)
    assert.equal(result.configError, false)
    assert.equal(result.confirmed, 2)
    assert.equal(result.precision, 0.667)
    assert.equal(result.costUsd, 0.47)
    assert.equal(result.surface, 59)
    assert.equal(result.facts, 65)
    assert.deepEqual(result.assignments, {
      total: 9, completed: 6, failed: 3, canceled: 0,
      investigationTotal: 6, investigationCompleted: 4, investigationFailed: 2,
    })
    assert.deepEqual(result.funnel, {
      targetVulns: 22, surfaceDiscovered: 20, hypothesisFormed: 9,
      signalObserved: 5, specSubmitted: 3, zeroLlmConfirmed: 0,
    })
    assert.equal(matrixExitCode([result]), 0)
  })

  test('inert agentic runs fail closed with exit 2', () => {
    const args = { outDir: tempDir('inert'), noLlm: false }
    const target = cell()
    writeArtifacts(args, target, { ...goodScorecard, confirmed: 0, totalCostUsd: 0 },
      { ...goodMeta, inert: true, facts: 0, endpointsDiscovered: 0 })
    const result = collectCellResult(target, args, { exitCode: 0, runtimeMs: 90_000, output: '' })
    assert.equal(result.ok, false)
    assert.equal(result.inert, true)
    assert.equal(result.configError, true)
    assert.match(result.error ?? '', /inert/i)
    assert.equal(matrixExitCode([result]), 2)
  })

  test('agentic request that silently fell back to deterministic fails closed', () => {
    const args = { outDir: tempDir('fallback'), noLlm: false }
    const target = cell()
    writeArtifacts(args, target, goodScorecard, { ...goodMeta, model: { mode: 'deterministic-no-llm' }, workerSessions: false })
    const result = collectCellResult(target, args, { exitCode: 0, runtimeMs: 60_000, output: '' })
    assert.equal(result.ok, false)
    assert.equal(result.configError, true)
    assert.match(result.error ?? '', /model profile/)
    assert.equal(matrixExitCode([result]), 2)
  })

  test('missing worker-session capability fails closed; deterministic cells do not need it', () => {
    const args = { outDir: tempDir('nosessions'), noLlm: false }
    const target = cell()
    writeArtifacts(args, target, goodScorecard, { ...goodMeta, workerSessions: false })
    const agentic = collectCellResult(target, args, { exitCode: 0, runtimeMs: 60_000, output: '' })
    assert.equal(agentic.configError, true)
    assert.match(agentic.error ?? '', /worker sessions/)
    const detArgs = { outDir: tempDir('det'), noLlm: true }
    writeArtifacts(detArgs, target, { ...goodScorecard, totalCostUsd: 0 }, { ...goodMeta, model: { mode: 'deterministic-no-llm' }, workerSessions: false, verifierBackend: 'local-jq' })
    const deterministic = collectCellResult(target, detArgs, { exitCode: 0, runtimeMs: 11_000, output: '' })
    assert.equal(deterministic.ok, true)
    assert.equal(deterministic.configError, false)
    assert.equal(matrixExitCode([deterministic]), 0)
  })

  test('locked data dir and missing scorecard are classified without raw output', () => {
    const args = { outDir: tempDir('lock'), noLlm: false }
    const target = cell()
    writeArtifacts(args, target, null, null)
    const locked = collectCellResult(target, args, {
      exitCode: 2, runtimeMs: 500,
      output: 'error: Guardian data dir is locked by another process (process-lock.sqlite)\nstack trace with raw paths',
    })
    assert.equal(locked.ok, false)
    assert.equal(locked.lockError, true)
    assert.equal(locked.configError, true)
    assert.ok((locked.error ?? '').length <= 200)
    assert.ok(!(locked.error ?? '').includes('stack trace'))
    assert.equal(matrixExitCode([locked]), 2)
    const missing = collectCellResult(target, { outDir: tempDir('missing'), noLlm: false }, { exitCode: 1, runtimeMs: 300, output: 'error: boom' })
    assert.equal(missing.ok, false)
    assert.equal(missing.configError, false)
    assert.match(missing.error ?? '', /scorecard missing/)
    assert.equal(matrixExitCode([missing]), 1)
  })
})

describe('aggregation and rendering', () => {
  test('summarize pools precision, cost/finding, funnel and worker-failure rate', () => {
    const args = { outDir: tempDir('agg'), noLlm: false }
    const a = cell()
    const b = cell({ app: 'shopflow', label: 'shopflow-seed1-grey-box' })
    writeArtifacts(args, a, goodScorecard, goodMeta)
    writeArtifacts(args, b, {
      confirmed: 0, targets: 20, precision: 1, decoyFalsePositives: 1, decoys: 5,
      unmatchedFalsePositives: 0, totalCostUsd: 0.23,
      funnel: { targetVulns: 20, surfaceDiscovered: 10, hypothesisFormed: 4, signalObserved: 1, specSubmitted: 0, zeroLlmConfirmed: 0 },
    }, {
      ...goodMeta, endpointsDiscovered: 40, facts: 12,
      assignments: { total: 4, completed: 2, failed: 2, canceled: 0, investigationTotal: 4, investigationCompleted: 0, investigationFailed: 4 },
    })
    const results = [
      collectCellResult(a, args, { exitCode: 0, runtimeMs: 120_000, output: '' }),
      collectCellResult(b, args, { exitCode: 0, runtimeMs: 80_000, output: '' }),
    ]
    const totals = summarizeMatrix(results)
    assert.equal(totals.cells, 2)
    assert.equal(totals.ok, 2)
    assert.equal(totals.confirmed, 2)
    assert.equal(totals.targets, 42)
    assert.equal(totals.decoyFp, 1)
    assert.equal(totals.unmatchedFp, 1)
    assert.equal(totals.precision, 0.5) // 2 TP / (2 TP + 1 decoy + 1 unmatched)
    assert.ok(Math.abs(totals.costUsd - 0.7) < 1e-9)
    assert.ok(Math.abs((totals.costPerFinding ?? 0) - 0.35) < 1e-9)
    assert.equal(totals.surface, 99)
    assert.equal(totals.facts, 77)
    assert.equal(totals.assignmentsCompleted, 4)
    assert.equal(totals.assignmentsFailed, 6)
    assert.equal(totals.workerFailureRate, 0.6) // investigation failed 6 / (4 + 6)
    assert.deepEqual(totals.funnel, {
      targetVulns: 42, surfaceDiscovered: 30, hypothesisFormed: 13,
      signalObserved: 6, specSubmitted: 3, zeroLlmConfirmed: 0,
    })
    assert.equal(totals.failureBuckets.surface_miss, 2)
  })

  test('renderMatrixTable exposes the baseline columns; summary reports fail-closed counters', () => {
    const args = { outDir: tempDir('render'), noLlm: false }
    const target = cell()
    writeArtifacts(args, target, goodScorecard, goodMeta)
    const result = collectCellResult(target, args, { exitCode: 0, runtimeMs: 120_000, output: '' })
    const table = renderMatrixTable([result as MatrixCellResult])
    for (const column of ['cell', 'conf', 'prec', 'decoyFP', 'unmFP', 'cost', 'wall', 'surf', 'facts', 'assign', 'inert', 'ws']) {
      assert.ok(table.includes(column), `table missing ${column}`)
    }
    assert.match(table, /acme-saas-seed1-grey-box\s+2\/22/)
    const summary = renderMatrixSummary(summarizeMatrix([result]))
    assert.match(summary, /TOTAL cells=1 ok=1 failed=0 inert=0/)
    assert.match(summary, /workerFailureRate=33\.3%/)
    assert.match(summary, /cost\/finding=\$0\.235/)
  })
})
