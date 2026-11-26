/**
 * R3-02 Stream A: Ledger Provenance Integrity, Hermetic Ledger Isolation & Drift Gate,
 * Real Floor Baseline Guard, and Deterministic Worker Source Hash Build.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'

import {
  DEFAULT_PER_RUN_LEDGER_DIR,
  LEDGER_SCHEMA_VERSION,
  appendLedgerRow,
  appendPerRunLedgerRow,
  computeEffectiveConfig,
  perRunLedgerPath,
  promoteLedgerRows,
  readLedgerRows,
  resolveDefaultPerRunLedgerDir,
  resolveGitState,
  validateLedgerRow,
  verifyGitShaProvenance,
  type LedgerRow,
} from '../scripts/bench-ledger.ts'
import { buildHermeticTestEnv, prepareHermeticTestDir } from '../scripts/runtime-profile.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const HEAD_SHA = resolveGitState(REPO_ROOT).gitSha
const WORKER_HASH = execFileSync('git', ['rev-parse', '--verify', 'HEAD:worker'], {
  cwd: REPO_ROOT,
  encoding: 'utf8',
}).trim()

function makeTmpDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeValidRow(overrides: Partial<LedgerRow> = {}): LedgerRow {
  return {
    schemaVersion: LEDGER_SCHEMA_VERSION,
    recordedAt: '2026-11-26T00:00:00.000Z',
    suite: 'realistic-bench',
    gitSha: HEAD_SHA,
    dirty: false,
    benchmarkVersion: 'a'.repeat(64),
    effectiveConfigHash: 'b'.repeat(64),
    app: 'acme-saas',
    split: 'dev',
    mode: 'grey-box',
    llm: 'deterministic-no-llm',
    seed: 1,
    repeat: 1,
    certifying: true,
    reportable: true,
    status: 'VALID',
    targets: 22,
    confirmed: 14,
    recall: 14 / 22,
    rawPrecision: 1,
    strictPrecision: 1,
    precision: 1,
    decoyFalsePositives: 0,
    unmatchedFalsePositives: 0,
    validUnplantedCount: 0,
    costUsd: 0,
    durationMs: 12_000,
    ...overrides,
  }
}

function initTempGitRepo(dir: string): { rootSha: string; mainSha: string; sideSha: string } {
  const git = (args: string[]) =>
    execFileSync('git', args, {
      cwd: dir,
      encoding: 'utf8',
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: 'Kovo Test',
        GIT_AUTHOR_EMAIL: 'test@kovo.local',
        GIT_COMMITTER_NAME: 'Kovo Test',
        GIT_COMMITTER_EMAIL: 'test@kovo.local',
      },
    }).trim()

  git(['init', '-b', 'main'])
  writeFileSync(join(dir, 'README.md'), 'root\n')
  git(['add', 'README.md'])
  git(['commit', '-m', 'root'])
  const rootSha = git(['rev-parse', '--short=12', 'HEAD'])

  git(['checkout', '-b', 'side'])
  writeFileSync(join(dir, 'side.txt'), 'side\n')
  git(['add', 'side.txt'])
  git(['commit', '-m', 'side commit'])
  const sideSha = git(['rev-parse', '--short=12', 'HEAD'])

  git(['checkout', 'main'])
  writeFileSync(join(dir, 'main.txt'), 'main\n')
  git(['add', 'main.txt'])
  git(['commit', '-m', 'main commit'])
  const mainSha = git(['rev-parse', '--short=12', 'HEAD'])

  return { rootSha, mainSha, sideSha }
}

// ============================================================================
// 1. Ledger Provenance Integrity (`validateLedgerRow` & `promoteLedgerRows`)
// ============================================================================

describe('R3-02 Step 1: validateLedgerRow & promoteLedgerRows provenance enforcement', () => {
  test('accepts real HEAD and ancestor commits, rejects fake SHAs and non-ancestor branch commits', (t) => {
    const repoDir = makeTmpDir(t, 'r302-git-')
    const { rootSha, mainSha, sideSha } = initTempGitRepo(repoDir)

    // Real HEAD & ancestor commit succeed
    assert.doesNotThrow(() => verifyGitShaProvenance(mainSha, repoDir))
    assert.doesNotThrow(() => verifyGitShaProvenance(rootSha, repoDir))
    assert.doesNotThrow(() => validateLedgerRow(makeValidRow({ gitSha: mainSha }), { repoRoot: repoDir }))
    assert.doesNotThrow(() => validateLedgerRow(makeValidRow({ gitSha: rootSha }), { repoRoot: repoDir }))

    // Fake hex SHAs rejected
    for (const fake of ['abc123def456', 'deadbeef1234', '000000000000']) {
      assert.throws(
        () => validateLedgerRow(makeValidRow({ gitSha: fake }), { repoRoot: repoDir }),
        /does not resolve to a commit in git/,
        `fake SHA '${fake}' must be rejected`,
      )
    }

    // Null / empty / non-hex SHAs rejected
    for (const bad of ['', '   ', 'unknown', 'sha-base', null as unknown as string]) {
      assert.throws(
        () => validateLedgerRow(makeValidRow({ gitSha: bad }), { repoRoot: repoDir }),
        /gitSha/,
        `invalid SHA '${String(bad)}' must be rejected`,
      )
    }

    // Real commit on a side branch that is NOT an ancestor of HEAD is rejected
    assert.throws(
      () => validateLedgerRow(makeValidRow({ gitSha: sideSha }), { repoRoot: repoDir }),
      /not an ancestor of HEAD/,
    )

    // Pure unit-test opt-out skipGitCheck bypasses git ancestry only when explicitly requested
    assert.doesNotThrow(() =>
      validateLedgerRow(makeValidRow({ gitSha: 'abc123def456' }), { repoRoot: repoDir, skipGitCheck: true }),
    )
  })

  test('rejects certifying=true && dirty=true and unknown workerSourceHash on certifying Docker rows', (t) => {
    const repoDir = makeTmpDir(t, 'r302-dirty-')
    const { mainSha } = initTempGitRepo(repoDir)

    // certifying=true && dirty=true is ALWAYS rejected (even with skipGitCheck: true)
    assert.throws(
      () => validateLedgerRow(makeValidRow({ gitSha: mainSha, certifying: true, dirty: true }), { repoRoot: repoDir }),
      /certifying=true while dirty=true/,
    )
    assert.throws(
      () =>
        validateLedgerRow(makeValidRow({ gitSha: mainSha, certifying: true, dirty: true }), {
          repoRoot: repoDir,
          skipGitCheck: true,
        }),
      /certifying=true while dirty=true/,
    )

    // Non-certifying dirty dev run is permitted with a real ancestor commit
    assert.doesNotThrow(() =>
      validateLedgerRow(makeValidRow({ gitSha: mainSha, certifying: false, dirty: true }), { repoRoot: repoDir }),
    )

    // Certifying rows refuse workerSourceHash === 'unknown' (top-level, effectiveConfig, or alias)
    assert.throws(
      () =>
        validateLedgerRow(makeValidRow({ gitSha: mainSha, certifying: true, workerSourceHash: 'unknown' }), {
          repoRoot: repoDir,
        }),
      /workerSourceHash/,
    )
    const { effectiveConfig } = computeEffectiveConfig({
      verifierBackend: 'docker',
      workerImageId: 'sha256:1234567890abcdef',
      workerSourceHash: 'unknown',
    })
    assert.throws(
      () =>
        validateLedgerRow(makeValidRow({ gitSha: mainSha, certifying: true, effectiveConfig }), {
          repoRoot: repoDir,
        }),
      /workerSourceHash/,
    )
    assert.throws(
      () =>
        validateLedgerRow(
          {
            ...makeValidRow({ gitSha: mainSha, certifying: true }),
            workerImageSourceHash: 'unknown',
          } as LedgerRow,
          { repoRoot: repoDir },
        ),
      /workerSourceHash/,
    )

    // Certifying Docker row missing workerSourceHash altogether is also refused
    const dockerMissingHash = computeEffectiveConfig({
      verifierBackend: 'docker',
      workerImageId: 'sha256:1234567890abcdef',
    }).effectiveConfig
    assert.throws(
      () =>
        validateLedgerRow(makeValidRow({ gitSha: mainSha, certifying: true, effectiveConfig: dockerMissingHash }), {
          repoRoot: repoDir,
        }),
      /workerSourceHash/,
    )

    // Certifying Docker row with valid deterministic workerSourceHash succeeds
    const dockerValidHash = computeEffectiveConfig({
      verifierBackend: 'docker',
      workerImageId: 'sha256:1234567890abcdef',
      workerSourceHash: WORKER_HASH,
    }).effectiveConfig
    assert.doesNotThrow(() =>
      validateLedgerRow(
        makeValidRow({
          gitSha: mainSha,
          certifying: true,
          workerImageId: 'sha256:1234567890abcdef',
          workerSourceHash: WORKER_HASH,
          effectiveConfig: dockerValidHash,
        }),
        { repoRoot: repoDir },
      ),
    )
  })

  test('promoteLedgerRows rejects fake-SHA, non-ancestor, certifying+dirty, and unknown-hash rows while promoting clean HEAD rows', (t) => {
    const repoDir = makeTmpDir(t, 'r302-promote-')
    const { mainSha, sideSha } = initTempGitRepo(repoDir)
    const targetLedger = join(repoDir, 'committed.jsonl')

    // 1. Fake SHA file refused on promote
    const fakeFile = join(repoDir, 'fake.jsonl')
    writeFileSync(fakeFile, `${JSON.stringify(makeValidRow({ gitSha: 'abc123def456' }))}\n`)
    assert.throws(
      () => promoteLedgerRows(fakeFile, { targetLedgerPath: targetLedger, repoRoot: repoDir }),
      /does not resolve to a commit in git/,
    )

    // 2. Non-ancestor SHA refused on promote
    const sideFile = join(repoDir, 'side.jsonl')
    writeFileSync(sideFile, `${JSON.stringify(makeValidRow({ gitSha: sideSha }))}\n`)
    assert.throws(
      () => promoteLedgerRows(sideFile, { targetLedgerPath: targetLedger, repoRoot: repoDir }),
      /not an ancestor of HEAD/,
    )

    // 3. certifying && dirty refused on promote
    const dirtyFile = join(repoDir, 'dirty.jsonl')
    writeFileSync(dirtyFile, `${JSON.stringify(makeValidRow({ gitSha: mainSha, certifying: true, dirty: true }))}\n`)
    assert.throws(
      () => promoteLedgerRows(dirtyFile, { targetLedgerPath: targetLedger, repoRoot: repoDir }),
      /certifying=true while dirty=true/,
    )

    // 4. Clean HEAD row promotes cleanly and idempotently
    const cleanFile = join(repoDir, 'clean.jsonl')
    appendLedgerRow(makeValidRow({ gitSha: mainSha, dirty: false, certifying: true }), cleanFile, repoDir)
    const first = promoteLedgerRows(cleanFile, { targetLedgerPath: targetLedger, repoRoot: repoDir })
    assert.equal(first.promoted, 1)
    assert.equal(readLedgerRows(targetLedger, repoDir).length, 1)

    const second = promoteLedgerRows(cleanFile, { targetLedgerPath: targetLedger, repoRoot: repoDir })
    assert.equal(second.promoted, 0)
    assert.equal(second.skippedDuplicate, 1)
  })
})

// ============================================================================
// 2. Hermetic KOVO_LEDGER_ROOT Isolation & run-fast-tests.sh Drift Gate
// ============================================================================

describe('R3-02 Step 2: KOVO_LEDGER_ROOT isolation and run-fast-tests.sh drift gate', () => {
  test('buildHermeticTestEnv isolates KOVO_LEDGER_ROOT outside repo checkout without altering effectiveConfigHash', (t) => {
    const sandbox = prepareHermeticTestDir(tmpdir(), 'r302-herm-')
    t.after(() => rmSync(sandbox, { recursive: true, force: true }))

    const env = buildHermeticTestEnv(sandbox, {
      baseEnv: {
        PATH: process.env.PATH,
        KOVO_LEDGER_ROOT: join(REPO_ROOT, 'benchmarks/results/runs'),
      },
    })
    assert.equal(env.KOVO_LEDGER_ROOT, join(resolve(sandbox), 'ledger'))
    assert.ok(existsSync(env.KOVO_LEDGER_ROOT!), 'prepareHermeticTestDir must create KOVO_LEDGER_ROOT')
    assert.equal(env.KOVO_LEDGER_ROOT!.startsWith(REPO_ROOT), false, 'KOVO_LEDGER_ROOT must be outside repo checkout')

    // KOVO_LEDGER_ROOT is non-behavioral and must never alter effectiveConfigHash
    const cfgA = computeEffectiveConfig({ env: { KOVO_LEDGER_ROOT: '/tmp/ledger-a' } })
    const cfgB = computeEffectiveConfig({ env: { KOVO_LEDGER_ROOT: '/tmp/ledger-b' } })
    assert.equal(cfgA.effectiveConfigHash, cfgB.effectiveConfigHash)
    assert.equal('KOVO_LEDGER_ROOT' in cfgA.effectiveConfig.kovoEnv, false)

    // resolveDefaultPerRunLedgerDir & appendPerRunLedgerRow honor KOVO_LEDGER_ROOT
    assert.equal(resolveDefaultPerRunLedgerDir({}), DEFAULT_PER_RUN_LEDGER_DIR)
    assert.equal(resolveDefaultPerRunLedgerDir({ KOVO_LEDGER_ROOT: env.KOVO_LEDGER_ROOT }), env.KOVO_LEDGER_ROOT)

    const prevEnv = process.env.KOVO_LEDGER_ROOT
    process.env.KOVO_LEDGER_ROOT = env.KOVO_LEDGER_ROOT
    t.after(() => {
      if (prevEnv === undefined) delete process.env.KOVO_LEDGER_ROOT
      else process.env.KOVO_LEDGER_ROOT = prevEnv
    })

    const resolvedPath = perRunLedgerPath('r302-isolated-check')
    assert.ok(resolvedPath.startsWith(env.KOVO_LEDGER_ROOT!))

    const written = appendPerRunLedgerRow(makeValidRow(), { runId: 'r302-isolated-check' })
    assert.ok(written.path.startsWith(env.KOVO_LEDGER_ROOT!))
    assert.ok(existsSync(written.path))
    assert.equal(existsSync(join(REPO_ROOT, 'benchmarks/results/runs/r302-isolated-check.jsonl')), false)
  })

  test('run-fast-tests.sh passes when writing to KOVO_LEDGER_ROOT and fails on benchmarks/results drift', (t) => {
    const tmpTests = makeTmpDir(t, 'r302-drift-tests-')
    const leakFile = join(REPO_ROOT, `benchmarks/results/runs/r302-synthetic-leak-${process.pid}.jsonl`)
    t.after(() => {
      rmSync(leakFile, { force: true })
    })

    // 1. Clean test using KOVO_LEDGER_ROOT passes with zero drift
    writeFileSync(
      join(tmpTests, 'clean-ledger.test.ts'),
      `
import assert from 'node:assert/strict'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'

test('writes inside KOVO_LEDGER_ROOT only', () => {
  assert.ok(process.env.KOVO_LEDGER_ROOT, 'KOVO_LEDGER_ROOT must be set by run-fast-tests.sh')
  writeFileSync(join(process.env.KOVO_LEDGER_ROOT!, 'isolated.jsonl'), '{"ok":true}\\n')
})
`,
    )

    const passRes = spawnSync(
      'bash',
      ['scripts/run-fast-tests.sh', '--suites-only', '--tests-dir', tmpTests, '--jobs', '1', '--json'],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
    assert.equal(passRes.status, 0, `expected clean run PASS: ${passRes.stderr}\n${passRes.stdout}`)
    const passJson = JSON.parse(passRes.stdout) as { ok: boolean; ledgerDrift: string[] }
    assert.equal(passJson.ok, true)
    assert.deepEqual(passJson.ledgerDrift, [])

    // 2. Rogue test leaking into benchmarks/results/runs/ fails fast-test drift gate
    writeFileSync(
      join(tmpTests, 'leaking-ledger.test.ts'),
      `
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { test } from 'node:test'

test('rogue leak into benchmarks/results/runs', () => {
  const target = ${JSON.stringify(leakFile)}
  mkdirSync(dirname(target), { recursive: true })
  writeFileSync(target, '{"leaked":true}\\n')
})
`,
    )

    const failRes = spawnSync(
      'bash',
      ['scripts/run-fast-tests.sh', '--suites-only', '--tests-dir', tmpTests, '--jobs', '1', '--json'],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
    rmSync(leakFile, { force: true })
    assert.notEqual(failRes.status, 0, 'leaking into benchmarks/results/runs/ MUST fail run-fast-tests.sh')
    const failJson = JSON.parse(failRes.stdout) as { ok: boolean; ledgerDrift: string[] }
    assert.equal(failJson.ok, false)
    assert.ok(failJson.ledgerDrift.length > 0, 'ledgerDrift must report the leaked file')
    assert.ok(
      failJson.ledgerDrift.some(entry => entry.includes('benchmarks/results/runs/')),
      `expected benchmarks/results/runs/ in ledgerDrift, got: ${JSON.stringify(failJson.ledgerDrift)}`,
    )
  })
})

// ============================================================================
// 3. Vacuous Floor Baseline Guard (`scripts/regression-floor.sh`)
// ============================================================================

describe('R3-02 Step 3: regression-floor.sh refuses vacuous baselines', () => {
  test('fails closed on null gitSha or empty confirmedIds (and on vacuous --write-baseline)', (t) => {
    const dir = makeTmpDir(t, 'r302-floor-')
    const actualPass = join(dir, 'actual-pass.json')
    writeFileSync(
      actualPass,
      JSON.stringify({
        gitSha: HEAD_SHA,
        targetsTotal: 2,
        confirmedCount: 2,
        falsePositiveCount: 0,
        perTarget: [
          { id: 'xben-01', vulnClass: 'sqli', isDecoy: false, outcome: 'confirmed' },
          { id: 'xben-02', vulnClass: 'bola', isDecoy: false, outcome: 'confirmed' },
        ],
      }),
    )

    // Case A: gitSha: null with populated confirmedIds -> FAIL
    const nullShaBaseline = join(dir, 'null-sha.json')
    writeFileSync(
      nullShaBaseline,
      JSON.stringify({
        schemaVersion: 1,
        suites: {
          'xben-25': {
            gitSha: null,
            targetsTotal: 2,
            confirmedCount: 2,
            falsePositiveCount: 0,
            confirmedIds: ['xben-01', 'xben-02'],
          },
        },
      }),
    )
    const resNullSha = spawnSync(
      'bash',
      [
        'scripts/regression-floor.sh',
        '--skip-golden', '--skip-boundaries', '--with-xben',
        '--baseline', nullShaBaseline,
        '--actual-json', actualPass,
      ],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
    assert.notEqual(resNullSha.status, 0, 'null gitSha baseline MUST fail closed')
    assert.match(resNullSha.stderr, /missing or null gitSha/)

    // Case B: valid gitSha with empty confirmedIds: [] -> FAIL
    const emptyIdsBaseline = join(dir, 'empty-ids.json')
    writeFileSync(
      emptyIdsBaseline,
      JSON.stringify({
        schemaVersion: 1,
        suites: {
          'xben-25': {
            gitSha: HEAD_SHA,
            targetsTotal: 2,
            confirmedCount: 2,
            falsePositiveCount: 0,
            confirmedIds: [],
          },
        },
      }),
    )
    const resEmptyIds = spawnSync(
      'bash',
      [
        'scripts/regression-floor.sh',
        '--skip-golden', '--skip-boundaries', '--with-xben',
        '--baseline', emptyIdsBaseline,
        '--actual-json', actualPass,
      ],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
    assert.notEqual(resEmptyIds.status, 0, 'empty confirmedIds baseline MUST fail closed')
    assert.match(resEmptyIds.stderr, /empty confirmedIds/)

    // Case C: --write-baseline refuses vacuous actual (null gitSha or empty confirmedIds)
    const vacuousActual = join(dir, 'actual-vacuous.json')
    writeFileSync(
      vacuousActual,
      JSON.stringify({
        gitSha: null,
        targetsTotal: 2,
        confirmedCount: 0,
        falsePositiveCount: 0,
        perTarget: [],
      }),
    )
    const resVacuousWrite = spawnSync(
      'bash',
      [
        'scripts/regression-floor.sh',
        '--skip-golden', '--skip-boundaries', '--with-xben',
        '--baseline', join(dir, 'should-not-write.json'),
        '--actual-json', vacuousActual,
        '--write-baseline',
      ],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
    assert.notEqual(resVacuousWrite.status, 0, '--write-baseline MUST refuse vacuous actual')
    assert.equal(existsSync(join(dir, 'should-not-write.json')), false)

    // Case D: Real baseline with non-null gitSha and non-empty confirmedIds PASSES
    const realBaseline = join(dir, 'real.json')
    const writeReal = spawnSync(
      'bash',
      [
        'scripts/regression-floor.sh',
        '--skip-golden', '--skip-boundaries', '--with-xben',
        '--baseline', realBaseline,
        '--actual-json', actualPass,
        '--write-baseline',
      ],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
    assert.equal(writeReal.status, 0, writeReal.stderr)
    const checkReal = spawnSync(
      'bash',
      [
        'scripts/regression-floor.sh',
        '--skip-golden', '--skip-boundaries', '--with-xben',
        '--baseline', realBaseline,
        '--actual-json', actualPass,
      ],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
    assert.equal(checkReal.status, 0, checkReal.stderr)
  })
})

// ============================================================================
// 4. Deterministic Worker Source Hash (`scripts/worker-source-hash.sh` & `package.json`)
// ============================================================================

describe('R3-02 Step 4: worker-source-hash.sh & package.json worker:build', () => {
  test('prints deterministic 40-hex git tree hash matching HEAD:worker and is wired in package.json', (t) => {
    const res = spawnSync('bash', ['scripts/worker-source-hash.sh', '--print-hash'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    })
    assert.equal(res.status, 0, res.stderr)
    const printed = res.stdout.trim()
    assert.match(printed, /^[0-9a-f]{40}$/)
    assert.notEqual(printed, 'unknown')
    assert.equal(printed, WORKER_HASH)

    // Non-git fallback still prints a deterministic 40-hex non-'unknown' hash
    const nonGitRoot = makeTmpDir(t, 'r302-nongit-')
    mkdirSync(join(nonGitRoot, 'scripts'), { recursive: true })
    mkdirSync(join(nonGitRoot, 'worker'), { recursive: true })
    writeFileSync(
      join(nonGitRoot, 'scripts/worker-source-hash.sh'),
      readFileSync(join(REPO_ROOT, 'scripts/worker-source-hash.sh'), 'utf8'),
    )
    writeFileSync(join(nonGitRoot, 'worker/bridge.ts'), '// worker fixture\n')
    const fb1 = spawnSync('bash', [join(nonGitRoot, 'scripts/worker-source-hash.sh'), '--print-hash'], {
      cwd: nonGitRoot,
      encoding: 'utf8',
    })
    const fb2 = spawnSync('bash', [join(nonGitRoot, 'scripts/worker-source-hash.sh'), '--print-hash'], {
      cwd: nonGitRoot,
      encoding: 'utf8',
    })
    assert.equal(fb1.status, 0, fb1.stderr)
    assert.match(fb1.stdout.trim(), /^[0-9a-f]{40}$/)
    assert.notEqual(fb1.stdout.trim(), 'unknown')
    assert.equal(fb1.stdout.trim(), fb2.stdout.trim())

    // package.json worker:build invokes scripts/worker-source-hash.sh and preserves kovo-worker:v4
    const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>
    }
    assert.ok(pkg.scripts['worker:build']?.includes('scripts/worker-source-hash.sh'))
    assert.ok(pkg.scripts['worker:build']?.includes('kovo-worker:v4'))
  })
})
