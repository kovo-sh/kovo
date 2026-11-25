// Multi-seed soundness & leakage verification across all 4 multihop-saas archetypes.
// Default: seeds 1..5 across paygrid, shipforge, nexusiam, connecthub.
// Set GUARDIAN_MULTIHOP_FULL_SWEEP=1 to run the full 1..30 dev sweep.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ALL_ARCHETYPES,
  parseSweepCliArgs,
  renderSoundnessReport,
  runSoundnessSweep,
} from '../scripts/soundness-sweep.ts'

test('multi-seed dev soundness & leakage sweep across all 4 archetypes', async () => {
  const fullSweep = process.env.GUARDIAN_MULTIHOP_FULL_SWEEP === '1'
  const seedCount = fullSweep ? 30 : 5
  const devSeeds = Array.from({ length: seedCount }, (_, idx) => idx + 1)

  const report = await runSoundnessSweep({
    devSeeds,
    asyncLatencyMs: 5,
    concurrency: 4,
  })

  assert.equal(report.pass, true, `soundness failures: ${JSON.stringify(report.failures)}`)
  assert.deepEqual(report.failures, [])
  assert.equal(report.apps.length, ALL_ARCHETYPES.length)
  assert.equal(report.totals.cells, ALL_ARCHETYPES.length * seedCount)
  assert.equal(report.totals.vulnerableTotal, ALL_ARCHETYPES.length * 4 * seedCount)
  assert.equal(report.totals.vulnerablePassed, report.totals.vulnerableTotal)
  assert.equal(report.totals.receiptsVerified, report.totals.vulnerableTotal)
  assert.equal(report.totals.hardenedFailures, 0)
  assert.equal(report.totals.hardenedOracleEvents, 0)
  assert.equal(report.totals.twinsTotal, ALL_ARCHETYPES.length * 3 * seedCount)
  assert.equal(report.totals.twinsPassed, report.totals.twinsTotal)
  assert.equal(report.totals.twinFailures, 0)
  assert.equal(report.totals.twinTerminalEvents, 0)
  assert.equal(report.totals.leakageHits, 0)

  for (const row of report.byApp) {
    assert.equal(row.pass, true, `${row.app} failed soundness sweep`)
    assert.equal(row.vulnerablePassed, 4 * seedCount, row.app)
    assert.equal(row.receiptsVerified, 4 * seedCount, row.app)
    assert.equal(row.hardenedFailures, 0, row.app)
    assert.equal(row.twinsPassed, 3 * seedCount, row.app)
    assert.equal(row.leakageHits, 0, row.app)
  }

  const md = renderSoundnessReport(report, 'md')
  assert.match(md, /Status: \*\*PASS\*\*/)
  const json = JSON.parse(renderSoundnessReport(report, 'json')) as { pass: boolean; totals: { leakageHits: number } }
  assert.equal(json.pass, true)
  assert.equal(json.totals.leakageHits, 0)
})

test('salted held-out soundness & leakage sweep across all 4 archetypes', async () => {
  const previous = process.env.GUARDIAN_RB_HELDOUT_SALT
  process.env.GUARDIAN_RB_HELDOUT_SALT = 'unit-test-multihop-soundness-heldout-salt'
  try {
    const report = await runSoundnessSweep({
      devSeeds: [],
      heldOutSeeds: [1_000_001, 1_000_002],
      asyncLatencyMs: 5,
      concurrency: 4,
    })
    assert.equal(report.pass, true, `held-out failures: ${JSON.stringify(report.failures)}`)
    assert.equal(report.totals.vulnerablePassed, ALL_ARCHETYPES.length * 4 * 2)
    assert.equal(report.totals.receiptsVerified, ALL_ARCHETYPES.length * 4 * 2)
    assert.equal(report.totals.hardenedFailures, 0)
    assert.equal(report.totals.hardenedOracleEvents, 0)
    assert.equal(report.totals.twinFailures, 0)
    assert.equal(report.totals.twinTerminalEvents, 0)
    assert.equal(report.totals.leakageHits, 0)
  } finally {
    if (previous === undefined) delete process.env.GUARDIAN_RB_HELDOUT_SALT
    else process.env.GUARDIAN_RB_HELDOUT_SALT = previous
  }
})

test('CLI arg parsing rejects CLI salt and wires dev + held-out seed ranges cleanly', async () => {
  assert.throws(
    () => parseSweepCliArgs(['--held-out-salt', 'never-pass-on-cli']),
    /never pass the held-out salt/i,
  )
  const parsed = parseSweepCliArgs(['--seeds', '30', '--held-out', '3', '--apps', 'paygrid,connecthub'])
  assert.deepEqual(parsed.apps, ['paygrid', 'connecthub'])
  assert.equal(parsed.devSeeds.length, 30)
  assert.equal(parsed.devSeeds[0], 1)
  assert.equal(parsed.devSeeds[29], 30)
  assert.deepEqual(parsed.heldOutSeeds, [1_000_001, 1_000_002, 1_000_003])

  const previous = process.env.GUARDIAN_RB_HELDOUT_SALT
  delete process.env.GUARDIAN_RB_HELDOUT_SALT
  try {
    await assert.rejects(
      () => runSoundnessSweep({ devSeeds: [], heldOutSeeds: [1_000_001] }),
      /GUARDIAN_RB_HELDOUT_SALT/,
    )
  } finally {
    if (previous !== undefined) process.env.GUARDIAN_RB_HELDOUT_SALT = previous
  }
})
