/**
 * v8 Multi-Hop Smoke Battery contract tests (`scripts/smoke-multihop.ts`).
 *
 * Covers:
 *  - CLI flag parsing, defaults, and invalid flag rejection;
 *  - `--dry-run` exit-0 behavior (both JSON and text) with zero external processes started;
 *  - Pure `evaluateV8SmokeGates(report, baseline)` pass/fail semantics:
 *    - all-pass healthy 3-cell fixture
 *    - hardened-twin precision trap FP instant fail
 *    - lift cell precision drop / decoy / unmatched FP fail
 *    - crashes / worker failures / orphans fail
 *    - Hop-Depth Funnel non-regression (every stage H1 -> H2 -> H3 -> H4+ -> FinalOracle -> CompositeReceiptConfirmed)
 *    - budget cap (> $2.00/cell) fail
 *    - dead-end re-probe waste (> 5%) fail
 *  - Archetype rotation determinism (explicit selector, cellIndex cycling, UTC date determinism);
 *  - Compact table & Markdown report formatting.
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  DEFAULT_BUDGET_USD_PER_CELL,
  DEFAULT_MAX_DURATION_MS,
  DEV_ARCHETYPES,
  V8_TIER0_TEST_FILES,
  evaluateV8SmokeGates,
  formatHopFunnelLong,
  loadBaseline,
  main,
  normalizeHopFunnel,
  parseV8SmokeArgs,
  planTierOneCells,
  renderV8CompactTable,
  renderV8MarkdownSummary,
  resolveArchetype,
  type HopDepthFunnel,
  type V8CellMetrics,
  type V8SmokeBaseline,
  type V8SmokeGateReportInput,
  type V8SmokeReport,
} from '../scripts/smoke-multihop.ts'

const REPO_ROOT = join(import.meta.dirname, '..')
const tempRoot = mkdtempSync(join(tmpdir(), 'kovo-v8-smoke-test-'))
process.on('exit', () => rmSync(tempRoot, { recursive: true, force: true }))

function makeFunnel(overrides: Partial<HopDepthFunnel> = {}): HopDepthFunnel {
  return {
    h1: 6,
    h2: 5,
    h3: 4,
    h4Plus: 2,
    finalOracle: 3,
    compositeReceiptConfirmed: 3,
    ...overrides,
  }
}

function makeCell(overrides: Partial<V8CellMetrics> = {}): V8CellMetrics {
  return {
    id: 'archetype-lift',
    kind: 'lift',
    archetype: 'paygrid',
    mode: 'grey-box',
    targets: 4,
    confirmed: 2,
    precision: 1,
    decoyFalsePositives: 0,
    unmatchedFalsePositives: 0,
    hopFunnel: makeFunnel({ h1: 4, h2: 3, h3: 2, h4Plus: 1, finalOracle: 2, compositeReceiptConfirmed: 2 }),
    costUsd: 1.45,
    wallMs: 420_000,
    crashes: 0,
    workerFailures: 0,
    orphans: 0,
    deadEndReprobeWasteRate: 0.03,
    completedAssignments: 14,
    ...overrides,
  }
}

function makeHealthyReport(overrides: Partial<V8SmokeGateReportInput> = {}): V8SmokeGateReportInput {
  const lift = makeCell()
  const trap = makeCell({
    id: 'hardened-twin-trap',
    kind: 'trap',
    archetype: 'paygrid',
    mode: 'hardened-twin-trap',
    targets: 0,
    confirmed: 0,
    precision: 1,
    hopFunnel: { h1: 2, h2: 1, h3: 0, h4Plus: 0, finalOracle: 0, compositeReceiptConfirmed: 0 },
    costUsd: 0.72,
    wallMs: 260_000,
    deadEndReprobeWasteRate: 0.02,
    completedAssignments: 8,
  })
  const micro = makeCell({
    id: 'async-crypto-micro',
    kind: 'micro',
    archetype: 'paygrid',
    mode: 'grey-box',
    slice: 'async-pivot,derived-crypto',
    targets: 2,
    confirmed: 1,
    precision: 1,
    hopFunnel: { h1: 2, h2: 2, h3: 2, h4Plus: 1, finalOracle: 1, compositeReceiptConfirmed: 1 },
    costUsd: 0.88,
    wallMs: 310_000,
    deadEndReprobeWasteRate: 0.04,
    completedAssignments: 9,
  })
  return {
    args: {
      budgetUsdPerCell: DEFAULT_BUDGET_USD_PER_CELL,
      maxDurationMs: DEFAULT_MAX_DURATION_MS,
    },
    cells: [lift, trap, micro],
    aggregateHopFunnel: makeFunnel(),
    ...overrides,
  }
}

function gatesMap(report: V8SmokeGateReportInput, baseline?: V8SmokeBaseline | null): Map<string, boolean> {
  return new Map(evaluateV8SmokeGates(report, baseline).map(gate => [gate.id, gate.pass]))
}

// ---------------------------------------------------------------------------
// 1. CLI parsing & dry-run
// ---------------------------------------------------------------------------

test('CLI parsing: defaults, all documented flags, and strict validation', () => {
  const fixedNow = new Date('2026-03-01T12:00:00Z')
  const defaults = parseV8SmokeArgs([], fixedNow)
  assert.equal(defaults.tier, 1)
  assert.equal(defaults.archetype, 'rotate')
  assert.equal(defaults.mode, 'grey-box')
  assert.equal(defaults.budgetUsdPerCell, 2.0)
  assert.equal(defaults.maxDurationMs, 600_000)
  assert.equal(defaults.dryRun, false)
  assert.equal(defaults.json, false)
  assert.equal(defaults.baseline, undefined)
  assert.equal(defaults.seed, 1)
  assert.equal(defaults.help, false)

  const baselineFile = join(tempRoot, 'base.json')
  const explicit = parseV8SmokeArgs([
    '--tier', '0',
    '--archetype', 'shipforge',
    '--mode', 'white-box',
    '--budget-usd-per-cell', '1.75',
    '--max-duration-ms', '300000',
    '--dry-run',
    '--out-dir', join(tempRoot, 'out'),
    '--json',
    '--baseline', baselineFile,
    '--seed', '7',
    '--cell-index', '2',
  ])
  assert.equal(explicit.tier, 0)
  assert.equal(explicit.archetype, 'shipforge')
  assert.equal(explicit.mode, 'white-box')
  assert.equal(explicit.budgetUsdPerCell, 1.75)
  assert.equal(explicit.maxDurationMs, 300_000)
  assert.equal(explicit.dryRun, true)
  assert.equal(explicit.json, true)
  assert.equal(explicit.baseline, baselineFile)
  assert.equal(explicit.seed, 7)
  assert.equal(explicit.cellIndex, 2)

  // Support --flag=value form as well
  const eqForm = parseV8SmokeArgs(['--tier=1', '--archetype=nexusiam', '--mode=white-box'])
  assert.equal(eqForm.tier, 1)
  assert.equal(eqForm.archetype, 'nexusiam')
  assert.equal(eqForm.mode, 'white-box')

  assert.equal(parseV8SmokeArgs(['--help']).help, true)
  assert.equal(parseV8SmokeArgs(['-h']).help, true)

  assert.throws(() => parseV8SmokeArgs(['--tier', '2']), /--tier must be 0 or 1/)
  assert.throws(() => parseV8SmokeArgs(['--archetype', 'connecthub']), /--archetype must be/)
  assert.throws(() => parseV8SmokeArgs(['--mode', 'black-box']), /--mode must be grey-box or white-box/)
  assert.throws(() => parseV8SmokeArgs(['--budget-usd-per-cell', '0']), /positive number/)
  assert.throws(() => parseV8SmokeArgs(['--max-duration-ms', '-10']), /positive integer/)
  assert.throws(() => parseV8SmokeArgs(['--unknown-flag']), /unknown flag/)
  assert.throws(() => parseV8SmokeArgs(['positional']), /unexpected argument/)
})

test('--dry-run exits 0, plans all 3 Tier-1 cells + 6 Tier-0 tests, and starts zero external processes', async () => {
  const outDir = join(tempRoot, 'dry-run-out')
  const rawJson = execFileSync(
    process.execPath,
    [
      'scripts/smoke-multihop.ts',
      '--dry-run',
      '--tier', '1',
      '--archetype', 'paygrid',
      '--mode', 'white-box',
      '--out-dir', outDir,
      '--json',
    ],
    { cwd: REPO_ROOT, encoding: 'utf8' },
  )
  const parsed = JSON.parse(rawJson) as V8SmokeReport
  assert.equal(parsed.executionMode, 'dry-run')
  assert.equal(parsed.pass, true)
  assert.equal(parsed.tier0.workerGate, 'not-run')
  assert.equal(parsed.tier0.v8Tests.length, V8_TIER0_TEST_FILES.length)
  assert.ok(parsed.tier0.v8Tests.every(item => item.status === 'not-run'))
  assert.equal(parsed.plannedCells.length, 3)

  const liftPlan = parsed.plannedCells.find(plan => plan.kind === 'lift')
  const trapPlan = parsed.plannedCells.find(plan => plan.kind === 'trap')
  const microPlan = parsed.plannedCells.find(plan => plan.kind === 'micro')
  assert.ok(liftPlan && trapPlan && microPlan)
  assert.equal(liftPlan.archetype, 'paygrid')
  assert.equal(liftPlan.mode, 'white-box')
  assert.ok(liftPlan.args.includes('scripts/benchmark-multihop.ts'))
  assert.equal(trapPlan.mode, 'hardened-twin-trap')
  assert.ok(trapPlan.args.includes('hardened-twin-trap'))
  assert.ok(microPlan.slice?.includes('async-pivot'))
  assert.ok(microPlan.slice?.includes('derived-crypto'))
  assert.ok(parsed.notes.some(note => /zero external processes/i.test(note)))

  // Also test text output + in-process main() exit code 0
  const textOut = execFileSync(
    process.execPath,
    ['scripts/smoke-multihop.ts', '--dry-run', '--out-dir', join(tempRoot, 'dry-text')],
    { cwd: REPO_ROOT, encoding: 'utf8' },
  )
  assert.match(textOut, /smoke-multihop v1 \[dry-run\]/)
  assert.match(textOut, /hardened-twin-trap/)
  assert.match(textOut, /zero external processes/i)

  const exitCode = await main(['--dry-run', '--tier', '1', '--out-dir', join(tempRoot, 'dry-inproc')])
  assert.equal(exitCode, 0)
})

// ---------------------------------------------------------------------------
// 2. Archetype rotation determinism
// ---------------------------------------------------------------------------

test('archetype rotation is deterministic across explicit selectors, cellIndex, and UTC dates', () => {
  // Explicit selectors ignore cellIndex / date
  for (const arch of DEV_ARCHETYPES) {
    assert.equal(resolveArchetype(arch, { cellIndex: 0 }), arch)
    assert.equal(resolveArchetype(arch, { cellIndex: 1 }), arch)
    assert.equal(resolveArchetype(arch, { cellIndex: 2 }), arch)
  }

  // cellIndex cycles deterministically across paygrid -> shipforge -> nexusiam
  assert.equal(resolveArchetype('rotate', { cellIndex: 0 }), 'paygrid')
  assert.equal(resolveArchetype('rotate', { cellIndex: 1 }), 'shipforge')
  assert.equal(resolveArchetype('rotate', { cellIndex: 2 }), 'nexusiam')
  assert.equal(resolveArchetype('rotate', { cellIndex: 3 }), 'paygrid')
  assert.equal(resolveArchetype('rotate', { cellIndex: 4 }), 'shipforge')
  assert.equal(resolveArchetype('rotate', { cellIndex: 5 }), 'nexusiam')

  // Fixed UTC date is deterministic and consecutive days cover all 3 dev archetypes
  const d1 = new Date('2026-06-01T00:00:00Z')
  const d2 = new Date('2026-06-02T00:00:00Z')
  const d3 = new Date('2026-06-03T00:00:00Z')
  assert.equal(resolveArchetype('rotate', { date: d1 }), resolveArchetype('rotate', { date: d1 }))
  const covered = new Set([
    resolveArchetype('rotate', { date: d1 }),
    resolveArchetype('rotate', { date: d2 }),
    resolveArchetype('rotate', { date: d3 }),
  ])
  assert.equal(covered.size, 3)

  // planTierOneCells honors cellIndex determinism
  const args0 = parseV8SmokeArgs(['--archetype', 'rotate', '--cell-index', '1'])
  const plans = planTierOneCells(args0)
  assert.equal(plans[0]!.archetype, 'shipforge')
  assert.equal(plans[1]!.archetype, 'shipforge')
})

// ---------------------------------------------------------------------------
// 3. Pure Gate Evaluator (`evaluateV8SmokeGates`)
// ---------------------------------------------------------------------------

test('evaluateV8SmokeGates: all gates PASS on a healthy 3-cell fixture (with & without baseline)', () => {
  const healthy = makeHealthyReport()
  const gatesNoBase = evaluateV8SmokeGates(healthy)
  assert.deepEqual(
    gatesNoBase.filter(gate => !gate.pass),
    [],
    JSON.stringify(gatesNoBase, null, 2),
  )

  const baseline: V8SmokeBaseline = {
    aggregateHopFunnel: makeFunnel({ h1: 6, h2: 5, h3: 4, h4Plus: 2, finalOracle: 3, compositeReceiptConfirmed: 3 }),
  }
  const gatesWithBase = evaluateV8SmokeGates(healthy, baseline)
  assert.deepEqual(
    gatesWithBase.filter(gate => !gate.pass),
    [],
    JSON.stringify(gatesWithBase, null, 2),
  )

  // Improved funnel over baseline must also pass
  const improved = makeHealthyReport({
    aggregateHopFunnel: makeFunnel({ h1: 8, h2: 6, h3: 5, h4Plus: 3, finalOracle: 4, compositeReceiptConfirmed: 4 }),
  })
  assert.equal(gatesMap(improved, baseline).get('hop-funnel-non-regression'), true)
})

test('evaluateV8SmokeGates: hardened-twin trap FP triggers INSTANT FAIL', () => {
  const trapConfirmed = makeHealthyReport()
  trapConfirmed.cells = trapConfirmed.cells.map(cell =>
    cell.kind === 'trap' ? { ...cell, confirmed: 1, precision: 0 } : cell,
  )
  const gates = evaluateV8SmokeGates(trapConfirmed)
  const trapGate = gates.find(gate => gate.id === 'hardened-twin-trap-zero')
  assert.ok(trapGate)
  assert.equal(trapGate.pass, false)
  assert.match(trapGate.observed, /INSTANT FAIL/)

  // Even a decoy FP with confirmed=0 fails the trap gate
  const trapDecoy = makeHealthyReport()
  trapDecoy.cells = trapDecoy.cells.map(cell =>
    cell.kind === 'trap' ? { ...cell, decoyFalsePositives: 1 } : cell,
  )
  assert.equal(gatesMap(trapDecoy).get('hardened-twin-trap-zero'), false)
})

test('evaluateV8SmokeGates: lift precision drop and decoy/unmatched FPs fail', () => {
  const badPrec = makeHealthyReport()
  badPrec.cells = badPrec.cells.map(cell =>
    cell.kind === 'lift' ? { ...cell, precision: 0.75, unmatchedFalsePositives: 1 } : cell,
  )
  assert.equal(gatesMap(badPrec).get('precision-lift'), false)

  const decoyOnMicro = makeHealthyReport()
  decoyOnMicro.cells = decoyOnMicro.cells.map(cell =>
    cell.kind === 'micro' ? { ...cell, decoyFalsePositives: 1 } : cell,
  )
  assert.equal(gatesMap(decoyOnMicro).get('precision-lift'), false)
})

test('evaluateV8SmokeGates: crashes, worker failures, orphans, and cell errors fail reliability gate', () => {
  const crashed = makeHealthyReport()
  crashed.cells[0] = { ...crashed.cells[0]!, crashes: 1 }
  assert.equal(gatesMap(crashed).get('zero-crashes-failures-orphans'), false)

  const workerFail = makeHealthyReport()
  workerFail.cells[1] = { ...workerFail.cells[1]!, workerFailures: 1 }
  assert.equal(gatesMap(workerFail).get('zero-crashes-failures-orphans'), false)

  const orphaned = makeHealthyReport()
  orphaned.cells[2] = { ...orphaned.cells[2]!, orphans: 2 }
  assert.equal(gatesMap(orphaned).get('zero-crashes-failures-orphans'), false)

  const errored = makeHealthyReport()
  errored.cells[0] = { ...errored.cells[0]!, error: 'harness exit 1' }
  assert.equal(gatesMap(errored).get('zero-crashes-failures-orphans'), false)
})

test('evaluateV8SmokeGates: Hop-Depth Funnel regression on any stage fails', () => {
  const baseline: V8SmokeBaseline = {
    aggregateHopFunnel: makeFunnel({ h1: 6, h2: 5, h3: 4, h4Plus: 2, finalOracle: 3, compositeReceiptConfirmed: 3 }),
  }

  const stages: Array<keyof HopDepthFunnel> = [
    'h1',
    'h2',
    'h3',
    'h4Plus',
    'finalOracle',
    'compositeReceiptConfirmed',
  ]
  for (const stage of stages) {
    const regressedFunnel = makeFunnel()
    regressedFunnel[stage] = Math.max(0, regressedFunnel[stage] - 1)
    // Keep two-side invariant valid when testing finalOracle regression
    if (stage === 'finalOracle') {
      regressedFunnel.compositeReceiptConfirmed = Math.min(
        regressedFunnel.compositeReceiptConfirmed,
        regressedFunnel.finalOracle,
      )
    }
    const report = makeHealthyReport({ aggregateHopFunnel: regressedFunnel })
    const gates = evaluateV8SmokeGates(report, baseline)
    const gate = gates.find(g => g.id === 'hop-funnel-non-regression')
    assert.ok(gate)
    assert.equal(gate.pass, false, `expected regression on stage '${stage}' to fail`)
    assert.match(gate.observed, /regression:/)
  }

  // Also test two-side violation (CompositeReceiptConfirmed > FinalOracle) fails even without baseline
  const impossible = makeHealthyReport({
    aggregateHopFunnel: makeFunnel({ finalOracle: 1, compositeReceiptConfirmed: 2 }),
  })
  assert.equal(gatesMap(impossible).get('hop-funnel-non-regression'), false)
})

test('evaluateV8SmokeGates: cost cap (> $2.00/cell) fails and exact cap ($2.00) passes', () => {
  const atCap = makeHealthyReport()
  atCap.cells[0] = { ...atCap.cells[0]!, costUsd: 2.0 }
  assert.equal(gatesMap(atCap).get('budget-cap'), true)

  const overCap = makeHealthyReport()
  overCap.cells[0] = { ...overCap.cells[0]!, costUsd: 2.01 }
  const gates = evaluateV8SmokeGates(overCap)
  const costGate = gates.find(gate => gate.id === 'budget-cap')
  assert.ok(costGate)
  assert.equal(costGate.pass, false)
  assert.match(costGate.observed, /over cap/)
})

test('evaluateV8SmokeGates: dead-end re-probe waste (> 5%) fails and exact 5% passes', () => {
  const atBoundary = makeHealthyReport()
  atBoundary.cells[2] = { ...atBoundary.cells[2]!, deadEndReprobeWasteRate: 0.05 }
  assert.equal(gatesMap(atBoundary).get('dead-end-reprobe-waste'), true)

  const overWaste = makeHealthyReport()
  overWaste.cells[2] = { ...overWaste.cells[2]!, deadEndReprobeWasteRate: 0.051 }
  const gates = evaluateV8SmokeGates(overWaste)
  const wasteGate = gates.find(gate => gate.id === 'dead-end-reprobe-waste')
  assert.ok(wasteGate)
  assert.equal(wasteGate.pass, false)
  assert.match(wasteGate.observed, /over cap/)
})

// ---------------------------------------------------------------------------
// 4. Baseline loader & compact table / Markdown summary rendering
// ---------------------------------------------------------------------------

test('baseline JSON loads cleanly and compact table + Markdown summary render funnel & gates', () => {
  const basePath = join(tempRoot, 'baseline-report.json')
  writeFileSync(basePath, JSON.stringify({ aggregateHopFunnel: makeFunnel() }, null, 2))
  const loaded = loadBaseline(basePath)
  assert.deepEqual(loaded?.aggregateHopFunnel, makeFunnel())
  assert.throws(() => loadBaseline(join(tempRoot, 'does-not-exist.json')), /could not read baseline JSON/)

  // PascalCase HopDepthFunnel from benchmark-multihop.ts normalizes cleanly
  assert.deepEqual(
    normalizeHopFunnel({ H1: 5, H2: 4, H3: 3, H4Plus: 2, FinalOracle: 2, CompositeReceiptConfirmed: 2 }),
    { h1: 5, h2: 4, h3: 3, h4Plus: 2, finalOracle: 2, compositeReceiptConfirmed: 2 },
  )

  const healthy = makeHealthyReport()
  const table = renderV8CompactTable(healthy.cells)
  assert.match(table, /archetype-lift/)
  assert.match(table, /hardened-twin-trap/)
  assert.match(table, /async-crypto-micro/)
  assert.match(table, /funnel\(H1\/H2\/H3\/H4\+\/O\/C\)/)

  const funnelLine = formatHopFunnelLong(makeFunnel())
  assert.equal(
    funnelLine,
    'H1=6 -> H2=5 -> H3=4 -> H4+=2 -> FinalOracle=3 -> CompositeReceiptConfirmed=3',
  )

  const report: V8SmokeReport = {
    version: 1,
    generatedAt: '2026-11-25T00:00:00.000Z',
    executionMode: 'run',
    gitSha: 'abcdef123456',
    args: {
      tier: 1,
      archetype: 'rotate',
      resolvedArchetype: 'paygrid',
      mode: 'grey-box',
      seed: 1,
      cellIndex: 0,
      budgetUsdPerCell: 2.0,
      maxDurationMs: 600_000,
      outDir: tempRoot,
      baselinePath: basePath,
    },
    tier0: {
      workerGate: 'pass',
      v8Tests: V8_TIER0_TEST_FILES.map(file => ({ file, status: 'pass', wallMs: 500 })),
      pass: true,
    },
    plannedCells: [],
    cells: healthy.cells,
    aggregateHopFunnel: makeFunnel(),
    gates: evaluateV8SmokeGates(healthy, loaded),
    totals: {
      confirmed: 3,
      trapConfirmed: 0,
      costUsd: 3.05,
      wallMs: 420_000,
      cells: 3,
      crashes: 0,
      workerFailures: 0,
      orphans: 0,
      maxDeadEndReprobeWasteRate: 0.04,
    },
    pass: true,
    notes: [],
  }
  const md = renderV8MarkdownSummary(report)
  assert.match(md, /# Kovo(?: Hunter)? v8 Multi-Hop Smoke Battery/)
  assert.match(md, /`hardened-twin-trap-zero`/)
  assert.match(md, /H1=6 -> H2=5 -> H3=4 -> H4\+=2 -> FinalOracle=3 -> CompositeReceiptConfirmed=3/)
})
