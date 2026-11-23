/**
 * v6 Phase-1 certification runner: verdict math, dedupe, ingestion and secret hygiene.
 *
 * The fixtures are synthetic report shapes (the same fields the real scorecards emit), so
 * the tests pin the *definitions* without spending model budget:
 *  - one PASS matrix and one FAIL fixture per gate (floor spread, preservation, precision,
 *    lift, reason-bench floor);
 *  - union/dedupe across independent runs, including enriched route+mutation keys;
 *  - `--from-dir` parsing of real-shaped summaries + per-cell meta + events DB;
 *  - salted held-out salt never appears in any rendered artifact.
 */
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { describe, test } from 'node:test'

import {
  CERTIFY_APPS,
  assertSecretFree,
  confirmedTargetKeys,
  evaluateCertification,
  ingestFromDirs,
  normalizeRoute,
  redactText,
  renderCertificateMarkdown,
  targetKey,
  unionConfirmedTargets,
} from '../scripts/certify-phase1.ts'
import type {
  Certificate,
  RealismRun,
  ReasonCellLike,
  ReasonRun,
  ScorecardLike,
  VulnLike,
} from '../scripts/certify-phase1.ts'

const TARGETS = 22

function siteId(app: string, index: number): string {
  return `${app}-site-${String(index).padStart(2, '0')}`
}

function vulnsFor(app: string, confirmed: number, targets = TARGETS): VulnLike[] {
  return Array.from({ length: targets }, (_, index) => ({
    siteId: siteId(app, index),
    vulnClass: 'bola',
    outcome: index < confirmed ? 'confirmed' : 'missed',
  }))
}

interface RunOverrides {
  app?: string
  seed?: number
  seedSet?: 'dev' | 'held-out'
  llm?: 'agentic' | 'deterministic-no-llm'
  confirmed?: number
  targets?: number
  precision?: number
  strictPrecision?: number
  incompatibleClassCount?: number
  misclassifiedFindingIds?: string[]
  floorConfirmed?: number | null
  floorLeadsEmitted?: number | null
  floorLeadsConsumed?: number | null
  vulns?: VulnLike[]
  id?: string
}

function realismRun(overrides: RunOverrides = {}): RealismRun {
  const app = overrides.app ?? 'acme-saas'
  const seed = overrides.seed ?? 1
  const seedSet = overrides.seedSet ?? (seed >= 1_000_000 ? 'held-out' : 'dev')
  const llm = overrides.llm ?? 'agentic'
  const targets = overrides.targets ?? TARGETS
  const confirmed = overrides.confirmed ?? 0
  const vulns = overrides.vulns ?? vulnsFor(app, confirmed, targets)
  const floorConfirmed = overrides.floorConfirmed === undefined ? confirmed : overrides.floorConfirmed
  return {
    id: overrides.id ?? `${llm}-${seedSet}-${app}-${seed}-${confirmed}-${Math.random()}`,
    dir: '/synthetic',
    file: null,
    app,
    seed,
    seedSet,
    mode: 'grey-box',
    llm,
    targets,
    confirmed,
    recall: confirmed / targets,
    precision: overrides.precision ?? 1,
    strictPrecision: overrides.strictPrecision ?? overrides.precision ?? 1,
    incompatibleClassCount: overrides.incompatibleClassCount ?? 0,
    misclassifiedFindingIds: overrides.misclassifiedFindingIds ?? [],
    decoyFalsePositives: 0,
    unmatchedFalsePositives: 0,
    confirmedKeys: confirmedTargetKeys(vulns, app),
    floor: {
      floorConfirmed: floorConfirmed === null ? null : floorConfirmed,
      floorLeadsConsumed: overrides.floorLeadsConsumed === undefined ? (floorConfirmed === null ? null : 5) : overrides.floorLeadsConsumed,
      floorLeadsEmitted: overrides.floorLeadsEmitted === undefined ? (floorConfirmed === null ? null : 5) : overrides.floorLeadsEmitted,
      source: 'synthetic',
    },
    notes: [],
  }
}

function reasonCell(
  app: string,
  llm: 'agentic' | 'deterministic-no-llm',
  confirmed: number,
  precision = 1,
): ReasonCellLike {
  const targets = 14
  return {
    app,
    seed: 1,
    mode: 'grey-box',
    llm,
    targets,
    confirmed,
    recall: confirmed / targets,
    precision,
    decoyFalsePositives: 0,
    unmatchedFalsePositives: 0,
    sites: Array.from({ length: targets }, (_, index) => ({
      siteId: `${app}-${String(index).padStart(2, '0')}`,
      confirmed: index < confirmed,
    })),
  }
}

function passReason(): ReasonRun[] {
  return [{
    source: 'synthetic-reason',
    cells: [
      reasonCell('ledgerflow', 'deterministic-no-llm', 0),
      reasonCell('forgecloud', 'deterministic-no-llm', 0),
      reasonCell('ledgerflow', 'agentic', 5),
      reasonCell('forgecloud', 'agentic', 6),
    ],
  }]
}

/** Full accepted matrix: floor n=3/app dev + n=1/app held-out, unified n=3/n=2. */
function passRuns(): RealismRun[] {
  const runs: RealismRun[] = []
  for (const app of CERTIFY_APPS) {
    for (const confirmed of [10, 10, 10]) {
      runs.push(realismRun({ app, seed: 1, seedSet: 'dev', llm: 'deterministic-no-llm', confirmed }))
    }
    runs.push(realismRun({ app, seed: 1_000_042, seedSet: 'held-out', llm: 'deterministic-no-llm', confirmed: 8 }))
    for (const confirmed of [12, 14, 16]) {
      runs.push(realismRun({ app, seed: 1, seedSet: 'dev', llm: 'agentic', confirmed, floorConfirmed: 10 }))
    }
    for (const confirmed of [12, 14]) {
      runs.push(realismRun({ app, seed: 1_000_042, seedSet: 'held-out', llm: 'agentic', confirmed, floorConfirmed: 8 }))
    }
  }
  return runs
}

function evaluate(runs: RealismRun[], reason: ReasonRun[] = passReason(), options: Omit<Parameters<typeof evaluateCertification>[2], 'mode'> = {}): Certificate {
  return evaluateCertification(runs, reason, {
    mode: 'from-dir',
    generatedAt: '2026-11-23T00:00:00.000Z',
    gitSha: 'test-sha',
    ...options,
  })
}

function criterion(cert: Certificate, id: string) {
  const found = cert.criteria.find(item => item.id === id)
  assert.ok(found, `missing criterion ${id}`)
  return found
}

describe('verdict: PASS matrix', () => {
  test('full accepted matrix certifies with the documented metric definitions', () => {
    const cert = evaluate(passRuns())
    assert.equal(cert.verdict, 'PASS', cert.criteria.filter(c => c.status === 'FAIL').map(c => `${c.id}: ${c.observed}`).join('; '))
    assert.ok(cert.criteria.every(item => item.status === 'PASS'))
    assert.equal(cert.floor.dev.perApp['acme-saas']?.confirmed, 10)
    assert.equal(cert.floor.dev.perApp['acme-saas']?.recall, 10 / TARGETS)
    assert.equal(cert.floor.dev.perApp['acme-saas']?.spreadTargets, 0)
    // Median per-run total (after deduping floor∩agent inside each run): 12/14/16 -> 14.
    // The union across runs (capability coverage) is 16; it is reported separately.
    assert.equal(cert.unified.dev.perApp['acme-saas']?.confirmed, 14)
    assert.equal(cert.unified.dev.perApp['acme-saas']?.recall, 14 / TARGETS)
    assert.equal(cert.unified.dev.perApp['acme-saas']?.coverageConfirmed, 16)
    assert.equal(cert.unified.dev.perApp['acme-saas']?.minRecall, 12 / TARGETS)
    assert.equal(cert.unified.dev.perApp['acme-saas']?.maxRecall, 16 / TARGETS)
    assert.ok((cert.lift.dev.aggregate ?? 0) > 0.15)
    assert.equal(cert.preservation.median, 1)
    assert.equal(cert.precision.worst, 1)
    assert.equal(cert.reason.floor.confirmed, 0)
    assert.equal(cert.reason.floor.targets, 28)
    assert.equal(cert.reason.agentic.confirmed, 11)
    assert.equal(cert.reason.agentic.recall, 11 / 28)
    assert.equal(cert.matrix.complete, true)
  })

  test('floor spread 2 targets fails the determinism gate', () => {
    const runs = passRuns()
    const floorRuns = runs.filter(run => run.llm === 'deterministic-no-llm' && run.seedSet === 'dev' && run.app === 'acme-saas')
    assert.equal(floorRuns.length, 3)
    const spreadRun = floorRuns[0]!
    spreadRun.confirmed = 8
    spreadRun.recall = 8 / TARGETS
    spreadRun.confirmedKeys = vulnsFor('acme-saas', 8).filter(v => v.outcome === 'confirmed').map(v => targetKey(v, 'acme-saas'))
    const cert = evaluate(runs)
    assert.equal(cert.floor.spread['acme-saas'], 2)
    assert.equal(criterion(cert, 'floor_spread').status, 'FAIL')
    assert.equal(cert.verdict, 'FAIL')
  })

  test('preservation 0.90 fails the floor-preservation gate', () => {
    const runs = passRuns().map(run => (
      run.llm === 'agentic' && run.seedSet === 'dev'
        ? { ...run, floor: { ...run.floor, floorConfirmed: 9 } }
        : run
    ))
    const cert = evaluate(runs)
    assert.equal(cert.preservation.median?.toFixed(2), '0.90')
    assert.equal(criterion(cert, 'floor_preservation').status, 'FAIL')
    assert.equal(cert.verdict, 'FAIL')
  })

  test('worst-run precision 0.95 fails the precision gate', () => {
    const runs = passRuns()
    const target = runs.find(run => run.llm === 'agentic')!
    target.precision = 0.95
    const cert = evaluate(runs)
    assert.equal(cert.precision.worst, 0.95)
    assert.equal(criterion(cert, 'worst_run_precision').status, 'FAIL')
    assert.equal(cert.verdict, 'FAIL')
  })

  test('dev lift shortfall (+4.5pp) fails the lift gate', () => {
    const runs = passRuns().map(run => (
      run.llm === 'agentic' && run.seedSet === 'dev'
        ? (() => {
          const vulns = vulnsFor(run.app, 11)
          return { ...run, confirmed: 11, recall: 11 / TARGETS, confirmedKeys: vulns.filter(v => v.outcome === 'confirmed').map(v => targetKey(v, run.app)) }
        })()
        : run
    ))
    const cert = evaluate(runs)
    assert.ok((cert.lift.dev.aggregate ?? 0) < 0.10)
    assert.equal(criterion(cert, 'agentic_lift_dev').status, 'FAIL')
    assert.equal(criterion(cert, 'agentic_lift_heldout').status, 'PASS')
    assert.equal(cert.verdict, 'FAIL')
  })

  test('reason-bench floor > 0 fails the 0/28 gate', () => {
    const reason: ReasonRun[] = [{
      source: 'synthetic',
      cells: [
        reasonCell('ledgerflow', 'deterministic-no-llm', 0),
        reasonCell('forgecloud', 'deterministic-no-llm', 1),
        reasonCell('ledgerflow', 'agentic', 5),
        reasonCell('forgecloud', 'agentic', 6),
      ],
    }]
    const cert = evaluate(passRuns(), reason)
    assert.equal(cert.reason.floor.confirmed, 1)
    assert.equal(cert.reason.floor.targets, 28)
    assert.equal(criterion(cert, 'reason_bench_floor').status, 'FAIL')
    assert.equal(cert.verdict, 'FAIL')
  })

  test('leads invariant fails when leads are emitted but never consumed', () => {
    const runs = passRuns().map(run => (
      run.llm === 'agentic' ? { ...run, floor: { ...run.floor, floorLeadsEmitted: 5, floorLeadsConsumed: 0 } } : run
    ))
    const cert = evaluate(runs)
    assert.equal(cert.leads.violations.length, 15)
    assert.equal(criterion(cert, 'leads_invariant').status, 'FAIL')
  })
})

describe('dedupe and metric math', () => {
  test('same target across runs is counted once in the union', () => {
    const first = realismRun({ app: 'acme-saas', confirmed: 1 })
    const second = realismRun({
      app: 'acme-saas', confirmed: 2, vulns: [
        { siteId: siteId('acme-saas', 0), vulnClass: 'bola', outcome: 'confirmed' },
        { siteId: siteId('acme-saas', 1), vulnClass: 'bola', outcome: 'confirmed' },
      ],
    })
    assert.equal(unionConfirmedTargets([first, second]).length, 2)
  })

  test('enriched route keys dedupe floor∩agent and normalize numeric/uuid ids', () => {
    const floorVuln: VulnLike = {
      siteId: 'truth-1', vulnClass: 'bola', outcome: 'confirmed',
      origin: 'http://127.0.0.1:4100/', route: '/api/items/1?debug=1',
      mutatedInput: { kind: 'param', name: 'ownerId' },
    }
    const sameTarget: VulnLike = {
      ...floorVuln, siteId: 'truth-1-agent', origin: 'http://127.0.0.1:4100',
      route: '/api/items/2', normalizedRoute: '/api/ITEMS/2',
    }
    const differentMutation: VulnLike = {
      ...floorVuln, siteId: 'truth-1-other', route: '/api/items/3',
      mutatedInput: { kind: 'param', name: 'projectId' },
    }
    assert.equal(targetKey(floorVuln, 'acme-saas'), targetKey(sameTarget, 'acme-saas'))
    assert.notEqual(targetKey(floorVuln, 'acme-saas'), targetKey(differentMutation, 'acme-saas'))
    assert.equal(normalizeRoute('/api/orders/123'), '/api/orders/:id')
    assert.equal(normalizeRoute('/api/orders/9f8c1b1e-1111-2222-3333-444455556666'), '/api/orders/:id')

    const floorRun = realismRun({
      app: 'acme-saas', llm: 'deterministic-no-llm', confirmed: 1, vulns: [floorVuln],
    })
    const agentRun = realismRun({
      app: 'acme-saas', llm: 'agentic', confirmed: 3,
      vulns: [sameTarget, { ...sameTarget, matchedFindingIds: ['duplicate'] }, differentMutation],
    })
    const cert = evaluate([floorRun, agentRun], [], { checkMatrix: false })
    const stats = cert.unified.dev.perApp['acme-saas']
    assert.ok(stats)
    assert.equal(agentRun.confirmedKeys.length, 2)
    assert.equal(stats.confirmed, 2) // floor target + one net-new mutation, duplicate collapsed
    assert.equal(stats.recall, 2 / TARGETS)
  })

  test('total product recall is deduped across independent runs (not summed)', () => {
    const runs = [
      realismRun({ app: 'acme-saas', llm: 'deterministic-no-llm', confirmed: 1 }),
      realismRun({ app: 'acme-saas', llm: 'agentic', confirmed: 1 }),
      realismRun({
        app: 'acme-saas', llm: 'agentic', confirmed: 2, vulns: [
          { siteId: siteId('acme-saas', 0), vulnClass: 'bola', outcome: 'confirmed' },
          { siteId: siteId('acme-saas', 1), vulnClass: 'bola', outcome: 'confirmed' },
        ],
      }),
    ]
    const cert = evaluate(runs, [], { checkMatrix: false })
    assert.ok(cert.unified.dev.perApp['acme-saas'])
    // Per-run deduped counts are 1 and 2 -> median 1.5, not the naive sum (3).
    assert.equal(cert.unified.dev.perApp['acme-saas']!.confirmed, 1.5)
    assert.equal(cert.unified.dev.perApp['acme-saas']!.recall, 1.5 / TARGETS)
    // Coverage across independent runs is the distinct union (2), reported separately.
    assert.equal(cert.unified.dev.perApp['acme-saas']!.coverageConfirmed, 2)
  })
})

describe('secret hygiene', () => {
  const salt = 'feedface00112233445566778899aabbccddeeff00112233'

  test('redacts the held-out salt from rendered certificate text', () => {
    const cert = evaluate(passRuns(), passReason(), { notes: [`raw salt=${salt}`] })
    const text = renderCertificateMarkdown(cert)
    assert.throws(() => assertSecretFree(text, [salt]), /secret/)
    const redacted = redactText(text, [salt])
    assert.ok(redacted.includes('[redacted]'))
    assert.equal(redacted.includes(salt), false)
    assert.doesNotThrow(() => assertSecretFree(redacted, [salt]))
  })

  test('refuses to write text that still contains the salt', () => {
    assert.throws(() => assertSecretFree(`oops ${salt}`, [salt]), /secret/)
  })
})

describe('class hygiene gate', () => {
  test('an incompatible class claim fails the certificate even at 100% standard precision', () => {
    const runs = passRuns()
    runs[0] = { ...runs[0]!, incompatibleClassCount: 1, strictPrecision: runs[0]!.precision }
    const cert = evaluate(runs)
    const gate = criterion(cert, 'class_hygiene')
    assert.equal(gate.status, 'FAIL')
    assert.match(gate.observed, /1 incompatible class claim/)
    assert.equal(cert.verdict, 'FAIL')
    assert.equal(cert.hygiene.incompatibleClassCount, 1)
  })

  test('sibling tolerance is visible: strict precision falls and the gate fails at 0 incompatible', () => {
    const runs = passRuns()
    runs[0] = { ...runs[0]!, misclassifiedFindingIds: ['misfiled'], strictPrecision: 0.5 }
    const cert = evaluate(runs)
    assert.equal(cert.hygiene.worstStrictPrecision, 0.5)
    assert.equal(cert.hygiene.misclassifiedRuns, 1)
    assert.equal(criterion(cert, 'class_hygiene').status, 'FAIL')
  })

  test('an artifact without the hygiene field fails (unmeasured, not assumed clean)', () => {
    const runs = passRuns()
    runs[0] = { ...runs[0]!, incompatibleClassCount: null }
    const cert = evaluate(runs)
    const gate = criterion(cert, 'class_hygiene')
    assert.equal(gate.status, 'FAIL')
    assert.match(gate.observed, /1 unmeasured/)
    assert.equal(cert.hygiene.incompatibleClassUnmeasured, 1)
    assert.equal(cert.verdict, 'FAIL')
  })

  test('clean matrix reports zero incompatible claims', () => {
    const cert = evaluate(passRuns())
    assert.equal(cert.hygiene.incompatibleClassCount, 0)
    assert.equal(cert.hygiene.worstStrictPrecision, 1)
    assert.equal(cert.hygiene.misclassifiedRuns, 0)
    assert.equal(criterion(cert, 'class_hygiene').status, 'PASS')
  })
})

describe('--from-dir ingestion', () => {
  test('parses real-shaped summary, per-cell meta and events DB', () => {
    const root = mkdtempSync(join(tmpdir(), 'guardian-certify-'))
    try {
      const card: ScorecardLike = {
        app: 'acme-saas', seed: 1, seedSet: 'dev', mode: 'grey-box',
        targets: TARGETS, confirmed: 2, recall: 2 / TARGETS, precision: 1,
        decoys: 6, decoyFalsePositives: 0, unmatchedFalsePositives: 0,
        vulns: vulnsFor('acme-saas', 2),
      }
      writeFileSync(join(root, 'summary.json'), JSON.stringify([card]))
      writeFileSync(join(root, 'acme-saas-seed1-grey-box.meta.json'), JSON.stringify({
        app: 'acme-saas', seed: 1, mode: 'grey-box', seedSet: 'dev',
        model: { mode: 'agentic', profiles: [{ name: 'synthetic' }] },
      }))
      const dbDir = join(root, 'data', 'acme-saas-seed1-grey-box')
      mkdirSync(dbDir, { recursive: true })
      const db = new DatabaseSync(join(dbDir, 'guardian.sqlite'))
      db.exec('create table events (kind text, detail text)')
      db.exec('create table facts (data text)')
      db.prepare('insert into events (kind, detail) values (?, ?)').run(
        'deterministic_lane.metrics',
        JSON.stringify({ reason: 'phase3', floorConfirmed: 2, floorLeadsConsumed: 3, laneWallMs: 10, floorRequests: 12 }),
      )
      for (let i = 0; i < 5; i += 1) {
        db.prepare('insert into facts (data) values (?)').run(JSON.stringify({ kind: 'det_lead' }))
      }
      db.close()

      const floorDir = join(root, 'floor')
      mkdirSync(floorDir)
      writeFileSync(join(floorDir, 'summary.json'), JSON.stringify([{
        ...card, app: 'shopflow', confirmed: 1, recall: 1 / TARGETS, vulns: vulnsFor('shopflow', 1),
      }]))

      const reasonDir = join(root, 'reason')
      mkdirSync(reasonDir)
      writeFileSync(join(reasonDir, 'reason-report.json'), JSON.stringify({
        schemaVersion: 1,
        generatedAt: '2026-11-23T00:00:00.000Z',
        gitSha: 'test-sha',
        cells: [reasonCell('ledgerflow', 'deterministic-no-llm', 0)],
        agentic: { confirmed: 0, targets: 14 },
        floorRun: { confirmed: 0, targets: 14 },
      }))

      const ingested = ingestFromDirs([root], {})
      assert.equal(ingested.runs.length, 2)
      const agentic = ingested.runs.find(run => run.app === 'acme-saas')
      assert.ok(agentic)
      assert.equal(agentic.llm, 'agentic')
      assert.equal(agentic.seedSet, 'dev')
      assert.equal(agentic.floor.floorConfirmed, 2)
      assert.equal(agentic.floor.floorLeadsConsumed, 3)
      assert.equal(agentic.floor.floorLeadsEmitted, 5)
      const floor = ingested.runs.find(run => run.app === 'shopflow')
      assert.ok(floor)
      assert.equal(floor.llm, 'deterministic-no-llm')
      assert.equal(ingested.reason.length, 1)
      assert.equal(ingested.reason[0]!.cells.length, 1)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test('a summary.json wins over sibling per-cell scorecards (no double count)', () => {
    const root = mkdtempSync(join(tmpdir(), 'guardian-certify-'))
    try {
      const card: ScorecardLike = {
        app: 'acme-saas', seed: 1, seedSet: 'dev', mode: 'grey-box',
        targets: TARGETS, confirmed: 1, recall: 1 / TARGETS, precision: 1,
        vulns: vulnsFor('acme-saas', 1),
      }
      writeFileSync(join(root, 'summary.json'), JSON.stringify([card]))
      writeFileSync(join(root, 'acme-saas-seed1-grey-box.json'), JSON.stringify(card))
      assert.doesNotThrow(() => ingestFromDirs([root], {}))
      const ingested = ingestFromDirs([root], {})
      assert.equal(ingested.runs.length, 1)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test('missing directory is rejected', () => {
    const missing = join(tmpdir(), `guardian-certify-missing-${Date.now()}`)
    assert.equal(existsSync(missing), false)
    assert.throws(() => ingestFromDirs([missing], {}), /does not exist/)
  })
})
