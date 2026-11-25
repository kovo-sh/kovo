/**
 * v7 smoke battery contract.
 *
 * Covers the pure, deterministic surface of `scripts/smoke-agentic.ts`:
 *  - three-tier flag parsing and dry-run safety;
 *  - every past over-claim archetype is dismissed by the shared Oracle invariants;
 *  - the zero-vuln trap fails on any confirmed vulnerability but ignores baseline hygiene;
 *  - gate pass/fail fixtures, including the single -1 net-new rerun allowance;
 *  - second-app rotation, snapshot-missing fallback to a cold run;
 *  - compact table/CSV shape and per-cell cost accounting.
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { test } from 'node:test'

import {
  assignmentP50Ms,
  bestSnapshotDir,
  confirmedVulnerabilityCounts,
  conversionOf,
  countCrashes,
  evaluateArchetype,
  evaluateGates,
  hasSnapshot,
  loadCorpus,
  main,
  microCapability,
  parseSmokeArgs,
  planTierOne,
  renderCompactTable,
  rotateSecondApp,
  runCorpus,
  spentUsd,
  toCsv,
  ROTATION_APPS,
  type Archetype,
  type CellMetrics,
  type GateInput,
} from '../scripts/smoke-agentic.ts'

const tempRoot = mkdtempSync(join(tmpdir(), 'kovo-smoke-test-'))
process.on('exit', () => rmSync(tempRoot, { recursive: true, force: true }))

function cell(overrides: Partial<CellMetrics> = {}): CellMetrics {
  return {
    id: 'lift',
    kind: 'lift',
    app: 'acme-saas',
    source: 'snapshot',
    targets: 22,
    confirmed: 11,
    precision: 1,
    decoyFalsePositives: 0,
    unmatchedFalsePositives: 0,
    netNew: 3,
    floorConfirmed: 11,
    floorPreserved: 11,
    conversion: 0.55,
    costUsd: 0.4,
    p50AssignmentMs: 60_000,
    completedAssignments: 14,
    wallMs: 300_000,
    crashes: 0,
    ...overrides,
  }
}

function gateInput(overrides: Partial<GateInput> = {}): GateInput {
  return {
    cells: [
      cell(),
      cell({ id: 'rotation', kind: 'rotation', app: 'shopflow', confirmed: 4, targets: 10, netNew: 1, costUsd: 0.3 }),
      cell({
        id: 'trap', kind: 'trap', app: 'zero-vuln', source: 'local', targets: 0, confirmed: 0,
        precision: 1, netNew: 0, floorConfirmed: 0, floorPreserved: null, conversion: null,
        costUsd: 0.1, p50AssignmentMs: null, completedAssignments: 3,
      }),
      cell({
        id: 'micro', kind: 'micro', app: 'wan-oob,staging-concurrency,monorepo-whitebox', source: 'local',
        targets: 3, confirmed: 2, precision: 1, netNew: null, floorConfirmed: null, floorPreserved: null,
        conversion: null, costUsd: 0.2, p50AssignmentMs: null, completedAssignments: 3,
        wiring: 'pass', capability: 2,
      }),
    ],
    liftBaseline: 2,
    baselineConversion: 0.5,
    trapConfirmed: 0,
    rerunExecuted: false,
    perCellBudgetUsd: 0.8,
    ...overrides,
  }
}

function gatesById(input: GateInput): Map<string, boolean> {
  return new Map(evaluateGates(input).map(gate => [gate.id, gate.pass]))
}

// ---------------------------------------------------------------------------
// Tier parsing / dry-run
// ---------------------------------------------------------------------------

test('tier parsing: defaults, explicit flags, and rejection of unknown flags', () => {
  const defaults = parseSmokeArgs([])
  assert.equal(defaults.tier, 1)
  assert.equal(defaults.seed, 1)
  assert.equal(defaults.durationSec, 300)
  assert.equal(defaults.trapDurationSec, 240)
  assert.ok(Number.isInteger(defaults.cellIndex) && defaults.cellIndex >= 0)
  assert.equal(defaults.budgetUsdPerCell, 0.8)

  const explicit = parseSmokeArgs([
    '--tier', '0', '--dry-run', '--cell-index', '0', '--seed', '42',
    '--duration-sec', '120', '--out-dir', '/tmp/out', '--lift-baseline', '0',
    '--skip-worker-gate', '--micro-fixtures', 'wan-oob',
  ])
  assert.equal(explicit.tier, 0)
  assert.equal(explicit.dryRun, true)
  assert.equal(explicit.seed, 42)
  assert.equal(explicit.durationSec, 120)
  assert.equal(explicit.skipWorkerGate, true)
  assert.deepEqual(explicit.microFixtures, ['wan-oob'])

  assert.equal(parseSmokeArgs(['--help']).help, true)
  assert.throws(() => parseSmokeArgs(['--tier', '3']), /--tier must be 0, 1 or 2/)
  assert.throws(() => parseSmokeArgs(['--bogus']), /unknown flag --bogus/)
  assert.throws(() => parseSmokeArgs(['--calibrate']), /requires --variants/)
  assert.throws(() => parseSmokeArgs(['--cell-index', '-1']), /non-negative integer/)
})

test('dry-run starts no model/worker/CLI process and exits 0', async () => {
  const out = join(tempRoot, 'dry')
  const stdout = execFileSync(process.execPath, [
    'scripts/smoke-agentic.ts', '--dry-run', '--tier', '0', '--skip-worker-gate',
    '--out-dir', out,
  ], { cwd: join(import.meta.dirname, '..'), encoding: 'utf8' })
  assert.match(stdout, /tier0 worker-gate=not-run corpus=pass/)
  assert.match(stdout, /dry-run: no model, worker, CLI or fixture runs were started/)
  // `main` is exported too; a second dry-run must remain side-effect free.
  const code = await main(['--dry-run', '--tier', '1', '--skip-worker-gate', '--out-dir', join(tempRoot, 'dry2')])
  assert.equal(code, 0)
})

// ---------------------------------------------------------------------------
// Tier 0 corpus
// ---------------------------------------------------------------------------

test('past over-claim archetypes are all dismissed by the Oracle invariants', () => {
  const corpus = loadCorpus(join(import.meta.dirname, '..', 'benchmarks/realism-suite/traps/fp-archetypes.json'))
  assert.ok(corpus.length >= 6, `expected >=6 archetypes, got ${corpus.length}`)
  const { results, pass } = runCorpus(join(import.meta.dirname, '..', 'benchmarks/realism-suite/traps/fp-archetypes.json'))
  assert.equal(pass, true, results.filter(result => !result.dismissed).map(result => `${result.id}: ${result.reason}`).join('\n'))
  const ids = new Set(results.map(result => result.id))
  for (const id of ['2fa-without-enrollment', 'amount-negative-echo', 'bfla-2xx-only', 'echo-mass-assign', 'bearer-csrf', 'public-route-tenant-canary']) {
    assert.ok(ids.has(id), `missing archetype ${id}`)
  }
  for (const result of results) {
    assert.equal(result.dismissed, true, `${result.id} must be dismissed: ${result.reason}`)
    assert.equal(result.satisfied, false)
    assert.ok(result.reason.length > 10)
  }
})

test('an over-claim archetype fixture flips the corpus gate (must-confirm-zero logic)', () => {
  const corpus = loadCorpus(join(import.meta.dirname, '..', 'benchmarks/realism-suite/traps/fp-archetypes.json'))
  // Turn the BFLA 2xx-only archetype into an actual confirmation: a real 2xx mutation with a
  // persisted protected-field change proves impact. The corpus evaluator must now flag it.
  const bfla = corpus.find(item => item.id === 'bfla-2xx-only')!
  const overClaim: Archetype = {
    ...bfla,
    id: 'bfla-real-impact',
    input: {
      impactClass: 'bfla',
      requiredRole: 'admin',
      steps: [
        { id: 'before', arm: 'control', method: 'GET', route: '/api/users/42', pathAndQuery: '/api/users/42', status: 200, actor: { handle: 'viewer', role: 'viewer', tenant: 'acme' }, json: { role: 'viewer', tenant_id: 'acme' } },
        { id: 'probe', arm: 'probe', method: 'PATCH', route: '/api/users/42', pathAndQuery: '/api/users/42', status: 200, actor: { handle: 'viewer', role: 'viewer', tenant: 'acme' }, requestJson: { role: 'admin' }, json: { ok: true, role: 'admin' } },
        { id: 'after', arm: 'control', method: 'GET', route: '/api/users/42', pathAndQuery: '/api/users/42', status: 200, actor: { handle: 'admin', role: 'admin', tenant: 'acme' }, json: { role: 'admin', tenant_id: 'acme' } },
      ],
    },
  }
  assert.equal(evaluateArchetype(overClaim).satisfied, true, 'real persisted impact must confirm')
})

// ---------------------------------------------------------------------------
// Trap / cost accounting
// ---------------------------------------------------------------------------

function makeFindingsDb(path: string, rows: Array<{ cls: string; kind?: string; superseded?: string | null }>): void {
  const db = new DatabaseSync(path)
  db.exec(`
    create table findings (
      id text primary key,
      verification_class text not null,
      finding_kind text not null default 'baseline_check',
      superseded_by_finding_id text
    );
    create table assignments (id text primary key, status text not null);
    create table runs (id text primary key, spent_usd real not null default 0);
    create table events (
      id integer primary key autoincrement,
      kind text not null,
      detail text not null,
      created_at integer not null
    );
  `)
  const insert = db.prepare('insert into findings (id, verification_class, finding_kind, superseded_by_finding_id) values (?, ?, ?, ?)')
  rows.forEach((row, index) => insert.run(`f${index}`, row.cls, row.kind ?? 'multi_step_chain', row.superseded ?? null))
  db.prepare("insert into assignments (id, status) values ('a1', 'complete'), ('a2', 'failed')").run()
  db.prepare("insert into runs (id, spent_usd) values ('r1', 0.42)").run()
  db.prepare("insert into events (kind, detail, created_at) values ('worker.started', '{\"assignmentId\":\"a1\"}', 1000)").run()
  db.prepare("insert into events (kind, detail, created_at) values ('worker.complete', '{\"assignmentId\":\"a1\"}', 61000)").run()
  db.prepare("insert into events (kind, detail, created_at) values ('worker.started', '{\"assignmentId\":\"a2\"}', 2000)").run()
  db.prepare("insert into events (kind, detail, created_at) values ('worker.failed', '{\"assignmentId\":\"a2\"}', 302000)").run()
  db.close()
}

test('zero-vuln trap: any confirmed vulnerability fails, baseline hygiene is ignored', () => {
  const clean = join(tempRoot, 'trap-clean.sqlite')
  makeFindingsDb(clean, [
    { cls: 'runtime_confirmed', kind: 'baseline_check' }, // HSTS-style hygiene, never a trap failure
    { cls: 'dismissed' },
    { cls: 'static_advisory' },
  ])
  assert.deepEqual(confirmedVulnerabilityCounts(clean), { confirmed: 0, advisory: 2, completedAssignments: 1 })

  const dirty = join(tempRoot, 'trap-dirty.sqlite')
  makeFindingsDb(dirty, [
    { cls: 'runtime_confirmed' },
    { cls: 'runtime_confirmed', superseded: 'newer' },
    { cls: 'pending_oob' },
  ])
  assert.equal(confirmedVulnerabilityCounts(dirty).confirmed, 1)
  const gates = gatesById(gateInput({ trapConfirmed: 1 }))
  assert.equal(gates.get('trap-zero'), false)
})

test('cost accounting reads per-run spend and gates the cap', () => {
  const path = join(tempRoot, 'cost.sqlite')
  makeFindingsDb(path, [])
  assert.equal(spentUsd(path), 0.42)
  assert.equal(spentUsd(join(tempRoot, 'absent.sqlite')), 0)

  assert.equal(gatesById(gateInput()).get('cost'), true)
  const over = gateInput({ cells: gateInput().cells.map(item => item.kind === 'rotation' ? { ...item, costUsd: 0.95 } : item) })
  assert.equal(gatesById(over).get('cost'), false)
})

test('p50 assignment and crash accounting use structured events/log text only', () => {
  const path = join(tempRoot, 'p50.sqlite')
  makeFindingsDb(path, [])
  // Durations: 60 s and 300 s -> p50 (median) = 180 s.
  assert.equal(assignmentP50Ms(path), 180_000)
  assert.equal(assignmentP50Ms(join(tempRoot, 'absent.sqlite')), null)
  assert.equal(countCrashes('all good'), 0)
  assert.equal(countCrashes('rpc call failed\nsandbox process crashed'), 2)
})

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

test('all gates pass on a healthy four-cell fixture', () => {
  const gates = evaluateGates(gateInput())
  assert.deepEqual(gates.filter(gate => !gate.pass), [], JSON.stringify(gates, null, 2))
})

test('gate fail fixtures: precision, trap, net-new, conversion, crashes, p50, throughput, cost', () => {
  assert.equal(gatesById(gateInput({ cells: gateInput().cells.map(item => item.kind === 'lift' ? { ...item, precision: 0.9 } : item) })).get('precision-lift'), false)
  assert.equal(gatesById(gateInput({ trapConfirmed: 0 })).get('trap-zero'), true)
  assert.equal(gatesById(gateInput({ trapConfirmed: 2 })).get('trap-zero'), false)

  assert.equal(gatesById(gateInput({ cells: gateInput().cells.map(item => item.kind === 'lift' ? { ...item, netNew: 1 } : item) })).get('paired-net-new'), false)
  // baseline 2 -> net-new 1 is exactly -1; only a rerun with non-regressed conversion allows it.
  const minusOneNoRerun = gateInput({ cells: gateInput().cells.map(item => item.kind === 'lift' ? { ...item, netNew: 1 } : item) })
  assert.equal(gatesById(minusOneNoRerun).get('paired-net-new'), false)
  const minusOneRerun = gateInput({
    cells: gateInput().cells.map(item => item.kind === 'lift' ? { ...item, netNew: 1, conversion: 0.5 } : item),
    rerunExecuted: true,
  })
  assert.equal(gatesById(minusOneRerun).get('paired-net-new'), true)

  const badConversion = gateInput({ cells: gateInput().cells.map(item => item.kind === 'lift' ? { ...item, conversion: 0.35 } : item) })
  assert.equal(gatesById(badConversion).get('conversion'), false)
  const noBaseline = gateInput({ baselineConversion: null })
  assert.equal(gatesById(noBaseline).get('conversion'), false)

  const crashed = gateInput({ cells: gateInput().cells.map(item => item.kind === 'rotation' ? { ...item, crashes: 1 } : item) })
  assert.equal(gatesById(crashed).get('crashes'), false)
  const errored = gateInput({ cells: gateInput().cells.map(item => item.kind === 'trap' ? { ...item, error: 'cli exit 1' } : item) })
  assert.equal(gatesById(errored).get('crashes'), false)

  const slow = gateInput({ cells: gateInput().cells.map(item => item.kind === 'lift' ? { ...item, p50AssignmentMs: 120_000 } : item) })
  assert.equal(gatesById(slow).get('p50-assignment'), false)
  const idle = gateInput({ cells: gateInput().cells.map(item => item.kind === 'lift' ? { ...item, completedAssignments: 11 } : item) })
  assert.equal(gatesById(idle).get('throughput'), false)
  assert.equal(gatesById(gateInput({ perCellBudgetUsd: 0.2 })).get('cost'), false)
})

// ---------------------------------------------------------------------------
// Rotation / snapshots
// ---------------------------------------------------------------------------

test('second app rotates by cell index and by date, never leaving the pair', () => {
  assert.deepEqual([...ROTATION_APPS].sort(), ['opsportal', 'shopflow'])
  const seen = new Set([0, 1, 2, 3, 4, 5].map(index => rotateSecondApp({ cellIndex: index })))
  assert.deepEqual([...seen].sort(), ['opsportal', 'shopflow'])
  const a = rotateSecondApp({ date: new Date('2026-01-01T00:00:00Z') })
  const b = rotateSecondApp({ date: new Date('2026-01-02T00:00:00Z') })
  assert.notEqual(a, b)
  assert.ok(ROTATION_APPS.includes(a) && ROTATION_APPS.includes(b))
})

test('snapshot-missing falls back to a cold run with snapshot capture', () => {
  const out = join(tempRoot, 'plan')
  const snapshots = join(out, 'snapshots')
  mkdirSync(snapshots, { recursive: true })
  const opts = parseSmokeArgs(['--out-dir', out, '--snapshot-root', snapshots, '--cell-index', '1'])
  const before = planTierOne(opts)
  assert.equal(before.find(plan => plan.kind === 'lift')!.source, 'cold')
  assert.equal(before.find(plan => plan.kind === 'rotation')!.source, 'cold')
  assert.deepEqual(before.find(plan => plan.kind === 'rotation')!.args, ['--app', 'opsportal'])

  const acme = join(snapshots, 'acme-saas-seed1-grey-box')
  mkdirSync(acme, { recursive: true })
  writeFileSync(join(acme, 'snapshot.json'), '{"schema":1}\n')
  assert.equal(hasSnapshot(acme), true)
  const after = planTierOne(opts)
  assert.equal(after.find(plan => plan.kind === 'lift')!.source, 'snapshot')
  assert.equal(after.find(plan => plan.kind === 'rotation')!.source, 'cold')

  // A planner-round checkpoint with floor confirmations is preferred over a pre-floor base copy.
  const round = join(acme, 'planner-round-1')
  mkdirSync(round, { recursive: true })
  writeFileSync(join(acme, 'snapshot.json'), '{"counts":{"runtimeConfirmed":0}}\n')
  writeFileSync(join(round, 'snapshot.json'), '{"counts":{"runtimeConfirmed":11}}\n')
  assert.equal(bestSnapshotDir(acme), round)
  assert.equal(planTierOne(opts).find(plan => plan.kind === 'lift')!.snapshot, round)
  assert.equal(bestSnapshotDir(join(tempRoot, 'missing')), null)
})

// ---------------------------------------------------------------------------
// Output shape / realism conversion
// ---------------------------------------------------------------------------

test('compact table and CSV expose the promised columns', () => {
  const cells = [cell(), cell({ id: 'trap', kind: 'trap', app: 'zero-vuln', source: 'local', confirmed: 0, targets: 0, netNew: 0, floorPreserved: null, conversion: null, completedAssignments: 2 })]
  const table = renderCompactTable(cells)
  const [header] = table.split('\n')
  for (const column of ['cell', 'app/source', 'conf/target', 'prec', 'net-new', 'preserved', 'conv', 'p50', 'done', 'cost']) {
    assert.ok(header!.includes(column), `missing column ${column}`)
  }
  assert.match(table, /zero-vuln\/local/)
  const csv = toCsv([{ variant: 'x', cell: 'lift', net_new: 2, cost_usd: 0.25 }])
  assert.equal(csv.split('\n')[0], 'variant,cell,net_new,cost_usd')
})

test('realism micro-slice reports wiring separately from capability', () => {
  const artifact = {
    metrics: {
      wiring: { status: 'pass' },
      oob: { blindSqliConfirmed: true, asyncSsrfConfirmed: false, asyncXxeConfirmed: false, webhookForgeryConfirmed: false },
    },
  }
  assert.equal(microCapability('wan-oob', artifact), 1)
  assert.equal(microCapability('staging-concurrency', { metrics: { staging: { writeBolaConfirmed: true, raceConfirmed: true } } }), 2)
  assert.equal(microCapability('monorepo-whitebox', { metrics: { monorepo: { fourHopConfirmations: 2 } } }), 2)
  assert.equal(microCapability('wan-oob', null), 0)
})

test('conversion is confirmed / submitted with a safe empty-baseline value', () => {
  assert.equal(conversionOf({ funnel: { specSubmitted: 10, zeroLlmConfirmed: 5 } }), 0.5)
  assert.equal(conversionOf({ funnel: { specSubmitted: 0, zeroLlmConfirmed: 0 } }), 0)
  assert.equal(conversionOf(null), null)
})
