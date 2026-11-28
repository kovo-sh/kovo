/**
 * Behavioral regression tests for `scripts/worker-gate.sh`, `scripts/merge-stream.sh`,
 * and `scripts/run-fast-tests.sh` speedups:
 *
 *  1. Narrow non-code diff (`.github/workflows/release.yml`, `docs/foo.md`):
 *     skips `tsc`, `check-unwired.ts`, and fast test suites while still running all fast
 *     static & trailer guards and exiting PASS cleanly. Touching `ARCHITECTURE.md` still
 *     runs `check-unwired.ts` while skipping `tsc` and fast tests.
 *  2. Narrow test-only diff (`tests/some-fast.test.ts` only):
 *     runs seeded incremental `tsc` and ONLY that touched test file (skipping unrelated suites).
 *  3. Code/config/helper/kernel/empty/invalid-base diffs:
 *     fail closed to FULL gate (`tsc` + `check-unwired.ts` + all fast suites), never scoping down.
 *  4. `KOVO_GATE_FULL=1` and `--full` (`worker-gate.sh` & `merge-stream.sh`):
 *     override narrow scoping and force full gate.
 *  5. Seeded `tsc --incremental` caching:
 *     produces `.kovo/tsc.tsbuildinfo` invisible to `git status --porcelain`, atomically updates
 *     `KOVO_TSC_CACHE_FILE` on clean `main` PASS and on `merge-stream.sh` fast-forward PASS
 *     (never on `--dry-run`), seeds & rebases paths into a second worktree at a different depth,
 *     recovers cleanly from a corrupt seed, and fails closed on a real TypeScript type error.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

const STATIC_CHECK_STUBS = [
  'check-v8-contamination.ts',
  'check-fixture-contamination.ts',
  'check-direct-db-writes.ts',
  'check-run-scoped-state.ts',
  'check-clones.ts',
  'check-function-growth.ts',
  'check-test-shape.ts',
  'check-security-optional.ts',
  'check-empty-catch.ts',
  'check-exhaustive.ts',
  'check-contract-change.ts',
  'check-verdict-flip.ts',
  'check-fix-provenance.ts',
  'check-unwired.ts',
  'check-kernel-review.ts',
] as const

interface ScopePlan {
  mode: 'full' | 'narrow'
  reason: string
  baseRef: string | null
  changedFiles: string[]
  runTsc: boolean
  runUnwired: boolean
  fastTestMode: 'full' | 'scoped' | 'skip'
  scopedTestFiles: string[]
}

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function createMiniGateRepo(t: { after: (fn: () => void) => void }): {
  repo: string
  git: (...args: string[]) => string
  baseSha: string
} {
  const repo = makeTempDir(t, 'kovo-gate-spd-')
  const git = (...args: string[]) =>
    execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()

  git('init', '-b', 'main')
  git('config', 'user.email', 'gate-speedups-test@example.invalid')
  git('config', 'user.name', 'Gate Speedups Tester')

  mkdirSync(join(repo, 'scripts'), { recursive: true })
  mkdirSync(join(repo, 'src/server'), { recursive: true })
  mkdirSync(join(repo, 'tests'), { recursive: true })
  mkdirSync(join(repo, 'plans'), { recursive: true })
  mkdirSync(join(repo, 'docs'), { recursive: true })
  mkdirSync(join(repo, '.github/workflows'), { recursive: true })
  mkdirSync(join(repo, 'build/server'), { recursive: true })
  mkdirSync(join(repo, 'build/client'), { recursive: true })
  writeFileSync(join(repo, 'build/server/server.js'), '// stub\n')

  writeFileSync(join(repo, '.gitignore'), 'node_modules\nnode_modules/\n/build/\n/.kovo/\n')
  writeFileSync(
    join(repo, 'package.json'),
    JSON.stringify({ name: 'mini-kovo-gate', private: true, type: 'module', scripts: { check: 'tsc --noEmit' } }, null, 2) + '\n',
  )
  writeFileSync(
    join(repo, 'tsconfig.json'),
    JSON.stringify(
      {
        compilerOptions: {
          target: 'ES2024',
          module: 'ESNext',
          moduleResolution: 'bundler',
          allowImportingTsExtensions: true,
          verbatimModuleSyntax: true,
          lib: ['ES2024'],
          types: ['node'],
          strict: true,
          skipLibCheck: true,
          noEmit: true,
        },
        include: ['src', 'tests'],
      },
      null,
      2,
    ) + '\n',
  )

  // Copy real gate scripts & test runner helpers under test.
  for (const rel of [
    'scripts/worker-gate.sh',
    'scripts/merge-stream.sh',
    'scripts/run-fast-tests.sh',
    'scripts/test-tiers.ts',
    'scripts/runtime-profile.ts',
    'scripts/kernel-manifest.json',
  ]) {
    copyFileSync(join(REPO_ROOT, rel), join(repo, rel))
  }

  // Lightweight stub static/trailer scripts that record every invocation to GATE_CHECK_LOG.
  for (const name of STATIC_CHECK_STUBS) {
    writeFileSync(
      join(repo, 'scripts', name),
      `import { appendFileSync } from 'node:fs'\n` +
        `const log = process.env.GATE_CHECK_LOG\n` +
        `if (log) appendFileSync(log, ${JSON.stringify(name)} + '\\n')\n` +
        `console.log(${JSON.stringify(`PASS: ${name}`)})\n`,
    )
  }

  // Minimal wiring-invariant anchor files + typed source module.
  writeFileSync(
    join(repo, 'src/server/execution.ts'),
    `export function evaluateDispatchStop(): boolean { return false }\n` +
      `export function planMultiTrialExpansion(): number { return 1 }\n`,
  )
  writeFileSync(
    join(repo, 'src/server/store.ts'),
    `export const TAG = 'invariant.confirmation_evidence'\n` +
      `export const SQL = 'findings_confirmation_evidence_insert'\n` +
      `export function enforceConfirmationEvidence(): boolean { return true }\n`,
  )
  writeFileSync(
    join(repo, 'src/mod.ts'),
    `export function addNumbers(a: number, b: number): number { return a + b }\n`,
  )

  writeFileSync(join(repo, 'plans/STREAM-BACKLOG.md'), '# Backlog\n\n| Stream | Status |\n| --- | --- |\n')
  writeFileSync(join(repo, 'ARCHITECTURE.md'), '# Architecture\n')
  writeFileSync(join(repo, 'docs/guide.md'), '# Guide\n')
  writeFileSync(join(repo, '.github/workflows/release.yml'), 'name: Release\n')
  writeFileSync(
    join(repo, 'tests/QUARANTINE.json'),
    JSON.stringify({ version: 2, maxQuarantinedCases: 0, entries: [] }, null, 2) + '\n',
  )

  // Placeholder files matching EXCLUDE_SPECS in run-fast-tests.sh so full-mode stale-exclude checks pass.
  const excludedPlaceholders = [
    'tests/boundaries.test.ts',
    'tests/v2-upgrades.test.ts',
    'tests/v3-boundaries.test.ts',
    'tests/v4-boundaries.test.ts',
    'tests/v4-e2e-tiers.test.ts',
    'tests/v4-m1-schema-verify-routing.test.ts',
    'tests/v4-m3-worker-sast-templates.test.ts',
    'tests/v4-m5-lab-iast-ui.test.ts',
    'tests/v5-gate-worker-lifecycle.test.ts',
    'tests/v5-m4-sast-templates-patch.test.ts',
    'tests/v6-verify.test.ts',
    'tests/e2e-ui-journeys.test.ts',
    'tests/ui-bucket-b1-state-settings.test.ts',
    'tests/ui-polish-foundation.test.ts',
    'tests/ui-polish-projects.test.ts',
    'tests/ui-polish-run-workbench.test.ts',
    'tests/v7-realism1-spa.test.ts',
    'tests/v8-seam1-golden-e2e.test.ts',
  ]
  for (const rel of excludedPlaceholders) {
    writeFileSync(join(repo, rel), '// excluded placeholder\n')
  }

  // Two fast behavioral tests: `some-fast.test.ts` and `unrelated-sentinel.test.ts`.
  // Both print deterministic markers into stdout (captured by TAP / summary) and check
  // `tests/some-fast.test.ts` vs `tests/unrelated-sentinel.test.ts`.
  writeFileSync(
    join(repo, 'tests/some-fast.test.ts'),
    `import assert from 'node:assert/strict'\n` +
      `import { test } from 'node:test'\n` +
      `import { addNumbers } from '../src/mod.ts'\n` +
      `test('some-fast adds numbers', () => {\n` +
      `  assert.equal(addNumbers(2, 3), 5)\n` +
      `})\n`,
  )
  writeFileSync(
    join(repo, 'tests/unrelated-sentinel.test.ts'),
    `import assert from 'node:assert/strict'\n` +
      `import { existsSync } from 'node:fs'\n` +
      `import { test } from 'node:test'\n` +
      `import { addNumbers } from '../src/mod.ts'\n` +
      `test('unrelated sentinel runs only in full gate', () => {\n` +
      `  assert.equal(addNumbers(10, 5), 15)\n` +
      `  if (existsSync('tests/.fail-unrelated-sentinel')) {\n` +
      `    assert.fail('UNRELATED_SENTINEL_EXECUTED')\n` +
      `  }\n` +
      `})\n`,
  )

  git('add', '.')
  git('commit', '-m', 'initial mini repo')
  const baseSha = git('rev-parse', 'HEAD')

  // Symlink node_modules AFTER initial commit (never tracked in git, matching real worktrees).
  symlinkSync(join(REPO_ROOT, 'node_modules'), join(repo, 'node_modules'))
  return { repo, git, baseSha }
}

function readPlan(repo: string, extraArgs: string[] = [], envOverrides: Record<string, string | undefined> = {}): ScopePlan {
  const env: NodeJS.ProcessEnv = { ...process.env }
  delete env.KOVO_GATE_FULL
  delete env.KOVO_GATE_BASE_REF
  delete env.KOVO_CONTRACT_BASE
  for (const [k, v] of Object.entries(envOverrides)) {
    if (v === undefined) delete env[k]
    else env[k] = v
  }
  const res = spawnSync('bash', ['scripts/worker-gate.sh', '--print-plan', ...extraArgs], {
    cwd: repo,
    env,
    encoding: 'utf8',
  })
  assert.equal(res.status, 0, `--print-plan failed: ${res.stderr}`)
  return JSON.parse(res.stdout) as ScopePlan
}

function runWorkerGate(
  cwd: string,
  extraArgs: string[] = [],
  envOverrides: Record<string, string | undefined> = {},
) {
  const env: NodeJS.ProcessEnv = { ...process.env }
  delete env.KOVO_GATE_FULL
  delete env.KOVO_GATE_BASE_REF
  delete env.KOVO_CONTRACT_BASE
  delete env.KOVO_TSC_CACHE_FILE
  delete env.KOVO_TSC_CACHE_DIR
  for (const [k, v] of Object.entries(envOverrides)) {
    if (v === undefined) delete env[k]
    else env[k] = v
  }
  return spawnSync('bash', ['scripts/worker-gate.sh', ...extraArgs], {
    cwd,
    env,
    encoding: 'utf8',
  })
}

describe('R3 gate speedups: narrow-diff scoping and seeded incremental tsc', { concurrency: true }, () => {
test('1. Narrow non-code diff (.github/workflows/release.yml + docs/foo.md) skips tsc, check-unwired, and fast suites while running static/trailer guards', (t) => {
  const { repo, git, baseSha } = createMiniGateRepo(t)
  const logDir = makeTempDir(t, 'kovo-checklog-')
  const checkLog = join(logDir, 'checks.log')
  const cacheFile = join(logDir, 'main.tsbuildinfo')

  // Arm sentinel: if full fast-test corpus runs, it will FAIL!
  git('checkout', '-b', 'feat/ci-docs-only')
  writeFileSync(join(repo, '.github/workflows/release.yml'), 'name: Release\n# tweaked\n')
  writeFileSync(join(repo, 'docs/foo.md'), '# New Doc\n')
  git('add', '.github/workflows/release.yml', 'docs/foo.md')
  git('commit', '-m', 'docs(ci): tweak release workflow and add docs/foo.md')

  // Verify sentinel does not break narrow non-code diff (even if build/ is a symlink like in merge-stream).
  const res = runWorkerGate(repo, [], {
    KOVO_GATE_BASE_REF: baseSha,
    GATE_CHECK_LOG: checkLog,
    KOVO_TSC_CACHE_FILE: cacheFile,
  })
  assert.equal(res.status, 0, `narrow non-code worker-gate failed:\n${res.stdout}\n${res.stderr}`)
  assert.ok(res.stdout.includes('mode=narrow'), `expected narrow mode in stdout:\n${res.stdout}`)
  assert.ok(res.stdout.includes('typecheck: SKIPPED (narrow non-TS diff: 2 files)'), `expected tsc SKIPPED:\n${res.stdout}`)
  assert.ok(res.stdout.includes('unwired-export ratchet: SKIPPED'), `expected check-unwired SKIPPED:\n${res.stdout}`)
  assert.ok(res.stdout.includes('fast-tests: SKIPPED (narrow non-code diff)'), `expected fast-tests SKIPPED:\n${res.stdout}`)
  assert.equal(existsSync(join(repo, '.kovo/tsc.tsbuildinfo')), false, 'tsc must not have run on non-TS diff')

  const ranChecks = readFileSync(checkLog, 'utf8').trim().split('\n')
  assert.ok(ranChecks.includes('check-contract-change.ts'), 'contract-change guard must still run')
  assert.ok(ranChecks.includes('check-verdict-flip.ts'), 'verdict-flip guard must still run')
  assert.ok(ranChecks.includes('check-fix-provenance.ts'), 'fix-provenance guard must still run')
  assert.ok(ranChecks.includes('check-v8-contamination.ts'), 'v8-contamination guard must still run')
  assert.equal(ranChecks.includes('check-unwired.ts'), false, 'check-unwired must be skipped when ARCHITECTURE.md untouched')

  // Touching ARCHITECTURE.md MUST still run check-unwired.ts (since it checks ARCHITECTURE.md citations) while skipping tsc + fast-tests.
  writeFileSync(checkLog, '')
  writeFileSync(join(repo, 'ARCHITECTURE.md'), '# Architecture\nUpdated section.\n')
  const archRes = runWorkerGate(repo, [], {
    KOVO_GATE_BASE_REF: baseSha,
    GATE_CHECK_LOG: checkLog,
    KOVO_TSC_CACHE_FILE: cacheFile,
  })
  assert.equal(archRes.status, 0, `ARCHITECTURE.md narrow gate failed:\n${archRes.stdout}\n${archRes.stderr}`)
  assert.ok(archRes.stdout.includes('typecheck: SKIPPED'), 'ARCHITECTURE.md still skips tsc')
  assert.ok(archRes.stdout.includes('fast-tests: SKIPPED'), 'ARCHITECTURE.md still skips fast tests')
  const archChecks = readFileSync(checkLog, 'utf8').trim().split('\n')
  assert.ok(archChecks.includes('check-unwired.ts'), 'ARCHITECTURE.md change MUST run check-unwired.ts')
})

test('2. Narrow test-only diff (tests/some-fast.test.ts) runs incremental tsc + ONLY the touched test file', (t) => {
  const { repo, git, baseSha } = createMiniGateRepo(t)
  const logDir = makeTempDir(t, 'kovo-testonly-')
  const cacheFile = join(logDir, 'main.tsbuildinfo')

  // Arm the unrelated sentinel by committing a marker on main? Instead, put a failing unrelated test on main!
  writeFileSync(
    join(repo, 'tests/unrelated-sentinel.test.ts'),
    `import assert from 'node:assert/strict'\n` +
      `import { test } from 'node:test'\n` +
      `test('unrelated sentinel fails if full corpus runs', () => {\n` +
      `  assert.fail('UNRELATED_SENTINEL_MUST_NOT_RUN')\n` +
      `})\n`,
  )
  git('add', 'tests/unrelated-sentinel.test.ts')
  git('commit', '-m', 'arm unrelated sentinel on main')
  const armedBase = git('rev-parse', 'HEAD')
  assert.notEqual(armedBase, baseSha)

  // Branch touching ONLY `tests/some-fast.test.ts`.
  git('checkout', '-b', 'feat/test-only')
  writeFileSync(
    join(repo, 'tests/some-fast.test.ts'),
    `import assert from 'node:assert/strict'\n` +
      `import { test } from 'node:test'\n` +
      `import { addNumbers } from '../src/mod.ts'\n` +
      `test('some-fast adds numbers', () => {\n` +
      `  assert.equal(addNumbers(4, 6), 10)\n` +
      `})\n`,
  )
  git('add', 'tests/some-fast.test.ts')
  git('commit', '-m', 'test: update some-fast assertion')

  const res = runWorkerGate(repo, [], {
    KOVO_GATE_BASE_REF: armedBase,
    KOVO_TSC_CACHE_FILE: cacheFile,
  })
  assert.equal(res.status, 0, `narrow test-only gate should pass without running unrelated sentinel:\n${res.stdout}\n${res.stderr}`)
  assert.ok(res.stdout.includes('mode=narrow'), `expected narrow mode:\n${res.stdout}`)
  assert.ok(res.stdout.includes('PASS: typecheck (incremental'), `expected tsc to run on test-only diff:\n${res.stdout}`)
  assert.ok(res.stdout.includes('Scoped fast-test run: 1/1 file(s) selected'), `expected scoped 1/1 fast-test run:\n${res.stdout}`)
  assert.ok(res.stdout.includes('1/1 files passed, 0 failed'), `expected exactly 1 test file executed:\n${res.stdout}`)
  assert.equal(res.stdout.includes('UNRELATED_SENTINEL_MUST_NOT_RUN'), false)

  // Introduce a TypeScript type error in `tests/some-fast.test.ts` -> MUST fail tsc!
  writeFileSync(
    join(repo, 'tests/some-fast.test.ts'),
    `import assert from 'node:assert/strict'\n` +
      `import { test } from 'node:test'\n` +
      `import { addNumbers } from '../src/mod.ts'\n` +
      `test('some-fast type error', () => {\n` +
      `  assert.equal(addNumbers('bad', 6), 10)\n` +
      `})\n`,
  )
  const badRes = runWorkerGate(repo, [], {
    KOVO_GATE_BASE_REF: armedBase,
    KOVO_TSC_CACHE_FILE: cacheFile,
  })
  assert.notEqual(badRes.status, 0, 'type error in narrow test-only diff MUST fail worker-gate')
  assert.ok(badRes.stdout.includes('TS2345'), `expected TS2345 diagnostic:\n${badRes.stdout}`)
})

test('3. Code, config, test-helper, kernel, and empty/invalid-base diffs fail closed to FULL gate', (t) => {
  const { repo, git } = createMiniGateRepo(t)
  const logDir = makeTempDir(t, 'kovo-full-')
  const cacheFile = join(logDir, 'main.tsbuildinfo')

  // Arm unrelated sentinel on main so FULL gate provably executes it.
  writeFileSync(
    join(repo, 'tests/unrelated-sentinel.test.ts'),
    `import assert from 'node:assert/strict'\n` +
      `import { test } from 'node:test'\n` +
      `test('unrelated sentinel proves full corpus ran', () => {\n` +
      `  assert.fail('FULL_CORPUS_RAN_SENTINEL')\n` +
      `})\n`,
  )
  git('add', 'tests/unrelated-sentinel.test.ts')
  git('commit', '-m', 'arm sentinel')
  const armedBase = git('rev-parse', 'HEAD')

  // 3a. Empty diff on clean main -> fail closed to full!
  const emptyPlan = readPlan(repo, [], { KOVO_GATE_BASE_REF: armedBase })
  assert.equal(emptyPlan.mode, 'full')
  assert.equal(emptyPlan.runTsc, true)
  assert.equal(emptyPlan.fastTestMode, 'full')

  // 3b. Invalid base ref -> fail closed to full!
  const badBasePlan = readPlan(repo, [], { KOVO_GATE_BASE_REF: 'nonexistent-ref-xyz' })
  assert.equal(badBasePlan.mode, 'full')
  assert.equal(badBasePlan.runTsc, true)
  assert.equal(badBasePlan.fastTestMode, 'full')

  // 3c. Verify EVERY code/config/helper/kernel category classifies as FULL.
  const fullTriggerFiles: Array<{ rel: string; content: string }> = [
    { rel: 'src/mod.ts', content: 'export function addNumbers(a: number, b: number): number { return a + b + 0 }\n' },
    { rel: 'scripts/extra-helper.ts', content: 'export const x = 1\n' },
    { rel: 'worker/tool.ts', content: 'export const w = 1\n' },
    { rel: 'benchmarks/bench.ts', content: 'export const b = 1\n' },
    { rel: 'public/asset.txt', content: 'hi\n' },
    { rel: 'tsconfig.json', content: readFileSync(join(repo, 'tsconfig.json'), 'utf8') + '\n' },
    { rel: 'package.json', content: readFileSync(join(repo, 'package.json'), 'utf8') + '\n' },
    { rel: 'tests/helpers/foo.ts', content: 'export const helper = 1\n' },
    { rel: 'tests/nested/orphan.test.ts', content: 'export const orphan = 1\n' },
    { rel: 'tests/parity/case.json', content: '{}\n' },
    { rel: 'tests/QUARANTINE.json', content: '{\n  "version": 2,\n  "maxQuarantinedCases": 0,\n  "entries": []\n}\n' },
    { rel: '.githooks/reference-transaction', content: '#!/usr/bin/env bash\n' },
    { rel: 'src/server/proof-receipt.ts', content: 'export const kernelFile = true\n' },
  ]

  for (const item of fullTriggerFiles) {
    git('reset', '--hard', armedBase)
    git('checkout', '-B', 'feat/probe-full', armedBase)
    git('clean', '-fd', '-e', 'node_modules', '-e', 'build')
    const abs = join(repo, item.rel)
    mkdirSync(resolve(abs, '..'), { recursive: true })
    writeFileSync(abs, item.content)
    const plan = readPlan(repo, [], { KOVO_GATE_BASE_REF: armedBase })
    assert.equal(plan.mode, 'full', `expected FULL gate for ${item.rel}, got: ${JSON.stringify(plan)}`)
    assert.equal(plan.runTsc, true, `expected tsc for ${item.rel}`)
    assert.equal(plan.runUnwired, true, `expected check-unwired for ${item.rel}`)
    assert.equal(plan.fastTestMode, 'full', `expected full fast tests for ${item.rel}`)
  }

  // 3d. End-to-end execution on a `src/mod.ts` change MUST run FULL corpus (hitting the unrelated sentinel!).
  git('reset', '--hard', armedBase)
  git('checkout', '-B', 'feat/src-change', armedBase)
  git('clean', '-fd', '-e', 'node_modules', '-e', 'build')
  writeFileSync(join(repo, 'src/mod.ts'), 'export function addNumbers(a: number, b: number): number { return a + b }\n// edit\n')
  git('add', 'src/mod.ts')
  git('commit', '-m', 'refactor: touch src/mod.ts')

  const srcRes = runWorkerGate(repo, [], {
    KOVO_GATE_BASE_REF: armedBase,
    KOVO_TSC_CACHE_FILE: cacheFile,
  })
  assert.notEqual(srcRes.status, 0, 'src/ diff must run full corpus and hit armed sentinel')
  assert.ok(srcRes.stdout.includes('mode=full (touches code/config path: src/mod.ts)'), `expected full mode for src/mod.ts:\n${srcRes.stdout}`)
  assert.ok(srcRes.stdout.includes('FULL_CORPUS_RAN_SENTINEL'), `expected unrelated sentinel to execute:\n${srcRes.stdout}`)
})

test('4. KOVO_GATE_FULL=1 and --full override narrow scoping in worker-gate.sh and merge-stream.sh', (t) => {
  const { repo, git } = createMiniGateRepo(t)
  const logDir = makeTempDir(t, 'kovo-override-')
  const stateDir = join(logDir, 'state')
  const checkLog = join(logDir, 'checks.log')
  const cacheFile = join(logDir, 'main.tsbuildinfo')

  // Arm unrelated sentinel on main.
  writeFileSync(
    join(repo, 'tests/unrelated-sentinel.test.ts'),
    `import assert from 'node:assert/strict'\n` +
      `import { test } from 'node:test'\n` +
      `test('sentinel proves --full ran all suites', () => {\n` +
      `  assert.fail('FORCED_FULL_HIT_SENTINEL')\n` +
      `})\n`,
  )
  git('add', 'tests/unrelated-sentinel.test.ts')
  git('commit', '-m', 'arm sentinel')
  const armedBase = git('rev-parse', 'HEAD')

  // Pure non-code branch that would normally narrow-scope and PASS.
  git('checkout', '-b', 'feat/docs-only')
  writeFileSync(join(repo, 'docs/foo.md'), '# Narrow docs change\n')
  git('add', 'docs/foo.md')
  git('commit', '-m', 'docs: add foo.md')

  // Sanity check: without override, narrow diff PASSES (sentinel skipped).
  const narrowRes = runWorkerGate(repo, [], {
    KOVO_GATE_BASE_REF: armedBase,
    GATE_CHECK_LOG: checkLog,
    KOVO_TSC_CACHE_FILE: cacheFile,
  })
  assert.equal(narrowRes.status, 0, `expected narrow pass without override:\n${narrowRes.stdout}\n${narrowRes.stderr}`)

  // `--full --print-plan` on worker-gate.sh forces mode=full.
  const fullFlagPlan = readPlan(repo, ['--full'], { KOVO_GATE_BASE_REF: armedBase })
  assert.equal(fullFlagPlan.mode, 'full')
  assert.equal(fullFlagPlan.runTsc, true)
  assert.equal(fullFlagPlan.fastTestMode, 'full')

  // `KOVO_GATE_FULL=1` forces FULL execution -> runs tsc + check-unwired + sentinel -> FAILS on sentinel!
  writeFileSync(checkLog, '')
  const envFullRes = runWorkerGate(repo, [], {
    KOVO_GATE_BASE_REF: armedBase,
    KOVO_GATE_FULL: '1',
    GATE_CHECK_LOG: checkLog,
    KOVO_TSC_CACHE_FILE: cacheFile,
  })
  assert.notEqual(envFullRes.status, 0, 'KOVO_GATE_FULL=1 must force full corpus and hit sentinel')
  assert.ok(envFullRes.stdout.includes('mode=full'), `expected mode=full:\n${envFullRes.stdout}`)
  assert.ok(envFullRes.stdout.includes('FORCED_FULL_HIT_SENTINEL'), `expected sentinel failure:\n${envFullRes.stdout}`)
  assert.ok(readFileSync(checkLog, 'utf8').includes('check-unwired.ts'), 'KOVO_GATE_FULL=1 must run check-unwired.ts')

  // `merge-stream.sh` without `--full` on pure docs branch -> narrow-scoped -> PASSES (dry-run)!
  git('checkout', 'main')
  const msNarrow = spawnSync(
    'bash',
    ['scripts/merge-stream.sh', 'feat/docs-only', '--base', 'main', '--dry-run', '--skip-ci-check', '--skip-kernel-review', '--json'],
    {
      cwd: repo,
      env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir, KOVO_TSC_CACHE_FILE: cacheFile },
      encoding: 'utf8',
    },
  )
  assert.equal(msNarrow.status, 0, `merge-stream narrow dry-run should pass:\n${msNarrow.stdout}\n${msNarrow.stderr}`)
  assert.ok(msNarrow.stderr.includes('mode=narrow'), `expected narrow mode inside merge-stream:\n${msNarrow.stderr}`)

  // `merge-stream.sh --full` on the SAME pure docs branch -> forces KOVO_GATE_FULL=1 -> hits sentinel -> FAILS!
  const msFull = spawnSync(
    'bash',
    ['scripts/merge-stream.sh', 'feat/docs-only', '--base', 'main', '--dry-run', '--full', '--skip-ci-check', '--skip-kernel-review', '--json'],
    {
      cwd: repo,
      env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir, KOVO_TSC_CACHE_FILE: cacheFile },
      encoding: 'utf8',
    },
  )
  assert.notEqual(msFull.status, 0, 'merge-stream --full must force full gate and hit sentinel')
  assert.ok(msFull.stderr.includes('mode=full'), `expected mode=full under merge-stream --full:\n${msFull.stderr}`)
  assert.ok(msFull.stderr.includes('FORCED_FULL_HIT_SENTINEL'), `expected sentinel hit under merge-stream --full:\n${msFull.stderr}`)
})

test('5. Seeded tsc --incremental caches cleanly across worktrees, stays invisible to git status, catches type errors, and refreshes atomically on main/merge-stream PASS', (t) => {
  const { repo, git } = createMiniGateRepo(t)
  const cacheDir = makeTempDir(t, 'kovo-tsc-cache-')
  const cacheFile = join(cacheDir, 'main.tsbuildinfo')
  const stateDir = join(cacheDir, 'state')

  // 5a. Run worker-gate.sh on clean `main` -> produces local `.kovo/tsc.tsbuildinfo`,
  //     atomically populates `KOVO_TSC_CACHE_FILE`, and keeps `git status --porcelain` clean!
  const mainRes = runWorkerGate(repo, [], {
    KOVO_GATE_FULL: '1',
    KOVO_TSC_CACHE_FILE: cacheFile,
  })
  assert.equal(mainRes.status, 0, `main worker-gate failed:\n${mainRes.stdout}\n${mainRes.stderr}`)
  const localInfo = join(repo, '.kovo/tsc.tsbuildinfo')
  assert.ok(existsSync(localInfo), 'local .kovo/tsc.tsbuildinfo must be created')
  assert.ok(existsSync(cacheFile), 'host seed cache KOVO_TSC_CACHE_FILE must be atomically written on clean main PASS')

  const seedParsed = JSON.parse(readFileSync(cacheFile, 'utf8')) as { fileNames: string[]; version: string }
  assert.ok(Array.isArray(seedParsed.fileNames) && seedParsed.fileNames.length > 0, 'seed tsbuildinfo must have fileNames')
  assert.ok(typeof seedParsed.version === 'string' && seedParsed.version.length > 0, 'seed tsbuildinfo must have TS version')
  assert.equal(git('status', '--porcelain'), '', 'git status --porcelain MUST remain 100% clean after incremental tsc')

  // 5b. Create a second detached worktree at a DIFFERENT nested path depth with symlinked node_modules.
  const wtParent = makeTempDir(t, 'kovo-wt-depth-')
  const wt2 = join(wtParent, 'nested/deep/wt2')
  mkdirSync(join(wtParent, 'nested/deep'), { recursive: true })
  git('worktree', 'add', '--quiet', '--detach', wt2, 'HEAD')
  t.after(() => {
    try {
      git('worktree', 'remove', '--force', wt2)
    } catch {}
  })
  symlinkSync(join(REPO_ROOT, 'node_modules'), join(wt2, 'node_modules'))

  // Touch a single test file in wt2 so incremental tsc runs seeded from `cacheFile`.
  writeFileSync(
    join(wt2, 'tests/some-fast.test.ts'),
    `import assert from 'node:assert/strict'\n` +
      `import { test } from 'node:test'\n` +
      `import { addNumbers } from '../src/mod.ts'\n` +
      `test('some-fast adds numbers in wt2', () => {\n` +
      `  assert.equal(addNumbers(7, 8), 15)\n` +
      `})\n`,
  )
  const wt2Res = runWorkerGate(wt2, [], {
    KOVO_GATE_BASE_REF: git('rev-parse', 'main'),
    KOVO_TSC_CACHE_FILE: cacheFile,
  })
  assert.equal(wt2Res.status, 0, `seeded wt2 worker-gate failed:\n${wt2Res.stdout}\n${wt2Res.stderr}`)
  assert.ok(wt2Res.stdout.includes('PASS: typecheck (incremental, seeded=1)'), `expected seeded=1 in wt2:\n${wt2Res.stdout}`)
  const wt2Info = join(wt2, '.kovo/tsc.tsbuildinfo')
  assert.ok(existsSync(wt2Info), 'wt2 must have its own local .kovo/tsc.tsbuildinfo')
  const wt2Parsed = JSON.parse(readFileSync(wt2Info, 'utf8')) as { fileNames: string[] }
  assert.ok(wt2Parsed.fileNames.some((f) => f.endsWith('src/mod.ts')), 'wt2 tsbuildinfo must include src/mod.ts')
  // Only our edited `tests/some-fast.test.ts` (never `.kovo/tsc.tsbuildinfo`) may show in git status!
  const wt2Status = execFileSync('git', ['status', '--porcelain'], { cwd: wt2, encoding: 'utf8' }).trim()
  assert.equal(wt2Status.includes('.kovo'), false, `.kovo/ must never appear in git status: ${wt2Status}`)

  // 5c. Deliberate type error in wt2 with warm cache MUST fail closed immediately!
  writeFileSync(
    join(wt2, 'tests/some-fast.test.ts'),
    `import { addNumbers } from '../src/mod.ts'\nexport const broken: string = addNumbers(1, 2)\n`,
  )
  const errRes = runWorkerGate(wt2, [], {
    KOVO_GATE_BASE_REF: git('rev-parse', 'main'),
    KOVO_TSC_CACHE_FILE: cacheFile,
  })
  assert.notEqual(errRes.status, 0, 'deliberate type error MUST fail even with warm incremental cache')
  assert.ok(errRes.stdout.includes('TS2322'), `expected TS2322 error diagnostic:\n${errRes.stdout}`)

  // 5d. Corrupt host seed cache recovers cleanly without failing typecheck.
  const corruptCache = join(cacheDir, 'corrupt.tsbuildinfo')
  writeFileSync(corruptCache, '{not valid json!!!')
  rmSync(join(repo, '.kovo/tsc.tsbuildinfo'), { force: true })
  const recoverRes = runWorkerGate(repo, [], {
    KOVO_GATE_FULL: '1',
    KOVO_TSC_CACHE_FILE: corruptCache,
  })
  assert.equal(recoverRes.status, 0, `corrupt seed cache should recover cleanly:\n${recoverRes.stdout}\n${recoverRes.stderr}`)
  const recoveredParsed = JSON.parse(readFileSync(corruptCache, 'utf8')) as { fileNames: string[] }
  assert.ok(Array.isArray(recoveredParsed.fileNames), 'clean main pass should replace corrupt seed with valid tsbuildinfo')

  // 5e. `merge-stream.sh` refreshes host seed cache on real fast-forward PASS (and NOT on `--dry-run`)
  //     and preserves valid `refs/notes/merge-gate` stamping!
  git('checkout', '-b', 'feat/add-helper', 'main')
  writeFileSync(
    join(repo, 'src/mod.ts'),
    `export function addNumbers(a: number, b: number): number { return a + b }\n` +
      `export function mulNumbers(a: number, b: number): number { return a * b }\n`,
  )
  git('add', 'src/mod.ts')
  git('commit', '-m', 'feat: add mulNumbers')
  const branchSha = git('rev-parse', 'HEAD')
  git('checkout', 'main')

  // Set cacheFile mtime far in the past so we can verify `--dry-run` does NOT overwrite it,
  // while real merge DOES overwrite it atomically.
  const oldTime = new Date('2020-01-01T00:00:00Z')
  utimesSync(cacheFile, oldTime, oldTime)
  const beforeDryMtime = statSync(cacheFile).mtimeMs

  const dryMs = spawnSync(
    'bash',
    ['scripts/merge-stream.sh', 'feat/add-helper', '--base', 'main', '--dry-run', '--skip-ci-check', '--skip-kernel-review', '--json'],
    {
      cwd: repo,
      env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir, KOVO_TSC_CACHE_FILE: cacheFile },
      encoding: 'utf8',
    },
  )
  assert.equal(dryMs.status, 0, `merge-stream dry-run failed:\n${dryMs.stdout}\n${dryMs.stderr}`)
  assert.equal(statSync(cacheFile).mtimeMs, beforeDryMtime, '--dry-run must NOT overwrite host seed cache')

  const realMs = spawnSync(
    'bash',
    ['scripts/merge-stream.sh', 'feat/add-helper', '--base', 'main', '--skip-ci-check', '--skip-kernel-review', '--json'],
    {
      cwd: repo,
      env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir, KOVO_TSC_CACHE_FILE: cacheFile },
      encoding: 'utf8',
    },
  )
  assert.equal(realMs.status, 0, `merge-stream real merge failed:\n${realMs.stdout}\n${realMs.stderr}`)
  assert.equal(git('rev-parse', 'main'), branchSha, 'main must fast-forward to branchSha')
  assert.ok(statSync(cacheFile).mtimeMs > beforeDryMtime, 'real merge-stream PASS must atomically refresh host seed cache')
  const mergeNote = git('notes', '--ref=refs/notes/merge-gate', 'show', branchSha)
  assert.ok(mergeNote.startsWith('merge-gate: PASS '), `expected valid merge-gate note, got: ${mergeNote}`)
})
})
