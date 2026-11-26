// @fixes R3-10
/**
 * R3-10 Stream A class-level guard suite:
 *   1. Monotone size ratchet (`scripts/check-function-growth.ts` + `scripts/size-baseline.json`)
 *      with shrink-only `--write-baseline`, prune-fail, and `Split-ticket:` trailer allowance.
 *   2. Fix provenance guard (`scripts/check-fix-provenance.ts`) verifying `Fixes: <ID>` trailers
 *      on confirmation-kernel commits and audit-ID subjects resolve in `plans/*.md`.
 *   3. AST cross-file clone guard (`scripts/check-clones.ts` + `scripts/clone-baseline.json`)
 *      with removal-only baseline and zero unticketed/non-kernel safety-primitive clones.
 *   4. Consolidated `src/server/safety-primitives.ts` strictest-semantics edge cases.
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { runCloneCheck } from '../scripts/check-clones.ts'
import {
  FALLBACK_CONFIRMATION_KERNEL_FILES,
  loadConfirmationKernelFiles,
  resolveIdInPlans,
  runFixProvenanceCheck,
} from '../scripts/check-fix-provenance.ts'
import {
  extractSplitTickets,
  loadSizeBaseline,
  runFunctionGrowthCheck,
} from '../scripts/check-function-growth.ts'
import {
  constantTimeStringEqual,
  isSensitiveRepoEntry,
  isSensitiveRepoRelativePath,
} from '../src/server/safety-primitives.ts'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function makeTempDir(t: test.TestContext, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function git(cwd: string, args: string[]): string {
  return execFileSync('git', ['-C', cwd, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim()
}

function initTempGitRepo(dir: string): void {
  execFileSync('git', ['init', '-b', 'main', dir], { stdio: 'ignore' })
  git(dir, ['config', 'user.email', 'qa@example.test'])
  git(dir, ['config', 'user.name', 'QA Bot'])
}

function runNodeScript(
  scriptRelPath: string,
  args: string[],
  cwd = REPO_ROOT,
): { status: number; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync(process.execPath, [join(REPO_ROOT, scriptRelPath), ...args], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    return { status: 0, stdout, stderr: '' }
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string }
    return {
      status: e.status ?? 1,
      stdout: typeof e.stdout === 'string' ? e.stdout : '',
      stderr: typeof e.stderr === 'string' ? e.stderr : '',
    }
  }
}

function makeFunctionSource(name: string, bodyStatements: number): string {
  const lines = Array.from({ length: bodyStatements }, (_, i) => `  const v${i} = ${i} + 1`)
  return `export function ${name}(): number {\n${lines.join('\n')}\n  return v0\n}\n`
}

// ---------------------------------------------------------------------------
// 1. Monotone Size Ratchet (check-function-growth.ts --baseline)
// ---------------------------------------------------------------------------

test('R3-10 Step 1: check-function-growth --baseline passes on HEAD with <=15 files over 4000L', () => {
  const report = runFunctionGrowthCheck({
    rootDir: REPO_ROOT,
    dir: 'src/server',
    baseline: true,
    commitMessages: ['chore: clean baseline verification'],
  })
  assert.equal(report.ok, true, `expected HEAD size baseline PASS, got error=${report.error}`)
  assert.ok(report.baselineEval)
  assert.equal(report.baselineEval.baselineExists, true)
  assert.equal(report.baselineEval.unticketedGrowthCount, 0)
  assert.equal(report.baselineEval.unprunedShrinkCount, 0)
  assert.ok(report.filesOver4000Lines <= 15, `files over 4000L must stay <= 15, got ${report.filesOver4000Lines}`)

  const cli = runNodeScript('scripts/check-function-growth.ts', ['--baseline'])
  assert.equal(cli.status, 0, `CLI --baseline failed: ${cli.stdout}\n${cli.stderr}`)
  assert.match(cli.stdout, /check-function-growth \[BASELINE\] PASS/)
})

test('R3-10 Step 1: rejects unticketed over-limit growth, accepts Split-ticket:, and enforces shrink-only baseline pruning', t => {
  const repo = makeTempDir(t, 'kovo-r3-10-size-')
  initTempGitRepo(repo)
  mkdirSync(join(repo, 'src', 'server'), { recursive: true })
  mkdirSync(join(repo, 'scripts'), { recursive: true })

  const samplePath = join(repo, 'src', 'server', 'big.ts')
  writeFileSync(samplePath, makeFunctionSource('bigHandler', 18))
  git(repo, ['add', '-A'])
  git(repo, ['commit', '-m', 'chore: initial fixture'])

  // Bootstrap baseline with low limits (maxFileLines=15, maxFnLines=10).
  const boot = runFunctionGrowthCheck({
    rootDir: repo,
    dir: 'src/server',
    maxFileLines: 15,
    maxFnLines: 10,
    writeBaseline: true,
  })
  assert.equal(boot.ok, true)
  const baseline = loadSizeBaseline(join(repo, 'scripts', 'size-baseline.json'))
  assert.ok(baseline)
  assert.equal(baseline.files['src/server/big.ts'], 22)
  assert.equal(baseline.functions['src/server/big.ts::bigHandler'], 21)

  // Clean check passes.
  const pass0 = runFunctionGrowthCheck({
    rootDir: repo,
    dir: 'src/server',
    maxFileLines: 15,
    maxFnLines: 10,
    baseline: true,
  })
  assert.equal(pass0.ok, true)

  // Grow bigHandler by 4 lines without Split-ticket: -> FAIL!
  writeFileSync(samplePath, makeFunctionSource('bigHandler', 22))
  git(repo, ['add', '-A'])
  git(repo, ['commit', '-m', 'fix: unticketed growth in bigHandler'])

  const failUnticketed = runNodeScript(
    'scripts/check-function-growth.ts',
    ['--root', repo, '--dir', 'src/server', '--max-file-lines', '15', '--max-fn-lines', '10', '--baseline'],
  )
  assert.equal(failUnticketed.status, 1, 'unticketed over-limit growth must fail')
  assert.match(failUnticketed.stdout, /FAIL-GROWTH/)

  // --write-baseline MUST refuse to grow an existing baseline (strictly shrink/removal-only).
  const refuseGrowWrite = runFunctionGrowthCheck({
    rootDir: repo,
    dir: 'src/server',
    maxFileLines: 15,
    maxFnLines: 10,
    writeBaseline: true,
  })
  assert.equal(refuseGrowWrite.ok, false)
  assert.match(refuseGrowWrite.error ?? '', /shrink\/removal-only/i)

  // Amend commit with `Split-ticket: R3-10` -> PASS!
  git(repo, ['commit', '--amend', '-m', 'fix: urgent security fix in bigHandler\n\nSplit-ticket: R3-10'])
  assert.deepEqual(extractSplitTickets(['msg\n\nSplit-ticket: R3-10']), ['R3-10'])
  assert.deepEqual(extractSplitTickets(['msg\n\nSplit-ticket:   ']), [])

  const passTicketed = runNodeScript(
    'scripts/check-function-growth.ts',
    ['--root', repo, '--dir', 'src/server', '--max-file-lines', '15', '--max-fn-lines', '10', '--baseline'],
  )
  assert.equal(passTicketed.status, 0, `expected Split-ticket growth to pass, got:\n${passTicketed.stdout}\n${passTicketed.stderr}`)
  assert.match(passTicketed.stdout, /splitTickets=\[R3-10\]/)

  // Shrink bigHandler below baseline (to 14 body statements = 17 fn lines) without pruning -> PRUNE-FAIL!
  writeFileSync(samplePath, makeFunctionSource('bigHandler', 14))
  git(repo, ['add', '-A'])
  git(repo, ['commit', '-m', 'refactor: shrink bigHandler'])

  const pruneFail = runFunctionGrowthCheck({
    rootDir: repo,
    dir: 'src/server',
    maxFileLines: 15,
    maxFnLines: 10,
    baseline: true,
  })
  assert.equal(pruneFail.ok, false)
  assert.ok((pruneFail.baselineEval?.unprunedShrinkCount ?? 0) > 0)

  // Shrink-only --write-baseline succeeds and updates baseline downward.
  const pruned = runFunctionGrowthCheck({
    rootDir: repo,
    dir: 'src/server',
    maxFileLines: 15,
    maxFnLines: 10,
    writeBaseline: true,
  })
  assert.equal(pruned.ok, true)
  const updated = loadSizeBaseline(join(repo, 'scripts', 'size-baseline.json'))
  assert.equal(updated?.functions['src/server/big.ts::bigHandler'], 17)

  const passAfterPrune = runFunctionGrowthCheck({
    rootDir: repo,
    dir: 'src/server',
    maxFileLines: 15,
    maxFnLines: 10,
    baseline: true,
  })
  assert.equal(passAfterPrune.ok, true)
})

// ---------------------------------------------------------------------------
// 2. Fix Provenance Guard (check-fix-provenance.ts)
// ---------------------------------------------------------------------------

test('R3-10 Step 2: check-fix-provenance enforces resolvable Fixes: on kernel & audit commits and supports kernel-manifest.json', t => {
  assert.equal(FALLBACK_CONFIRMATION_KERNEL_FILES.length, 20)

  const repo = makeTempDir(t, 'kovo-r3-10-prov-')
  initTempGitRepo(repo)
  mkdirSync(join(repo, 'src', 'server'), { recursive: true })
  mkdirSync(join(repo, 'plans'), { recursive: true })
  mkdirSync(join(repo, 'scripts'), { recursive: true })

  writeFileSync(
    join(repo, 'plans', 'claude_quality_3.md'),
    '# Quality Plan 3\n\n## 10. Monotone Size Ratchet\n`id: R3-10`\nRelated: `R4-H-8`\n',
  )
  writeFileSync(join(repo, 'src', 'server', 'oracle-invariants.ts'), 'export const v = 1\n')
  writeFileSync(join(repo, 'src', 'server', 'non-kernel.ts'), 'export const n = 1\n')
  git(repo, ['add', '-A'])
  git(repo, ['commit', '-m', 'chore: initial commit'])

  // Boundary precision: R3-1 must NOT resolve against R3-10.
  const docs = [{ file: 'plans/claude_quality_3.md', content: '`id: R3-10` and `R4-H-8`' }]
  assert.deepEqual(resolveIdInPlans('R3-10', docs), ['plans/claude_quality_3.md'])
  assert.deepEqual(resolveIdInPlans('R3-1', docs), [])

  // 1. Kernel commit WITHOUT Fixes: trailer -> FAIL.
  writeFileSync(join(repo, 'src', 'server', 'oracle-invariants.ts'), 'export const v = 2\n')
  git(repo, ['add', '-A'])
  git(repo, ['commit', '-m', 'fix: tweak oracle invariant'])
  const missingCli = runNodeScript('scripts/check-fix-provenance.ts', ['--root', repo, '--base', 'HEAD~1'])
  assert.equal(missingCli.status, 1)
  assert.match(missingCli.stderr, /missing_fixes_trailer/)

  // 2. Kernel commit with UNRESOLVABLE Fixes: R9-999 -> FAIL.
  git(repo, ['commit', '--amend', '-m', 'fix: tweak oracle invariant\n\nFixes: R9-999'])
  const unresolvableCli = runNodeScript('scripts/check-fix-provenance.ts', ['--root', repo, '--base', 'HEAD~1'])
  assert.equal(unresolvableCli.status, 1)
  assert.match(unresolvableCli.stderr, /unresolvable_fixes_id/)

  // 3. Kernel commit with RESOLVABLE Fixes: R3-10 -> PASS.
  git(repo, ['commit', '--amend', '-m', 'fix: tweak oracle invariant\n\nFixes: R3-10'])
  const validCli = runNodeScript('scripts/check-fix-provenance.ts', ['--root', repo, '--base', 'HEAD~1'])
  assert.equal(validCli.status, 0, `expected valid Fixes: R3-10 to pass:\n${validCli.stdout}\n${validCli.stderr}`)
  assert.match(validCli.stdout, /check-fix-provenance \[HEAD~1\.\.HEAD\] PASS/)

  // 4. Non-kernel commit whose subject references an audit ID (R4-H-8) without Fixes: -> FAIL.
  writeFileSync(join(repo, 'src', 'server', 'non-kernel.ts'), 'export const n = 2\n')
  git(repo, ['add', '-A'])
  git(repo, ['commit', '-m', 'fix(R4-H-8): tighten non-kernel helper'])
  const auditSubjFail = runFixProvenanceCheck({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(auditSubjFail.ok, false)
  assert.match(auditSubjFail.commits[0]?.violations[0] ?? '', /missing_fixes_trailer/)

  // 5. Ordinary non-kernel, non-audit commit without Fixes: -> PASS.
  git(repo, ['commit', '--amend', '-m', 'chore: tidy non-kernel comment'])
  const nonKernelPass = runFixProvenanceCheck({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(nonKernelPass.ok, true)

  // 6. Custom scripts/kernel-manifest.json overrides fallback kernel set.
  writeFileSync(
    join(repo, 'scripts', 'kernel-manifest.json'),
    JSON.stringify({ files: ['src/server/non-kernel.ts'] }),
  )
  const loaded = loadConfirmationKernelFiles(repo)
  assert.equal(loaded.source, 'manifest')
  assert.equal(loaded.files.has('src/server/non-kernel.ts'), true)
  const manifestFail = runFixProvenanceCheck({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(manifestFail.ok, false, 'manifest-listed file must require Fixes: trailer')
})

// ---------------------------------------------------------------------------
// 3. AST Clone Guard (check-clones.ts)
// ---------------------------------------------------------------------------

test('R3-10 Step 3: check-clones passes on HEAD with 0 safety-primitive AST clones and 0 constantTimeStringEqual/non-kernel isSensitiveRepoEntry duplicates', () => {
  const report = runCloneCheck({ rootDir: REPO_ROOT })
  assert.equal(report.ok, true, `expected HEAD check-clones PASS, error=${report.error}`)
  assert.equal(report.safetyPrimitiveAstCloneGroups.length, 0, '0 AST clones touching safety primitives')
  assert.equal(report.unticketedSafetyPrimitiveDuplicates.length, 0, '0 unticketed safety-primitive duplicates')
  assert.equal(report.newCloneGroups.length, 0)
  assert.equal(report.expandedCloneGroups.length, 0)
  assert.equal(report.resolvedCloneGroups.length, 0)
  assert.equal(report.shrunkCloneGroups.length, 0)

  // Verify 0 constantTimeStringEqual duplicates anywhere in src/server, and 0 non-kernel isSensitiveRepoEntry duplicates.
  const cteDups = report.safetyPrimitiveDuplicates.filter(d => d.name === 'constantTimeStringEqual')
  assert.deepEqual(cteDups, [], 'constantTimeStringEqual must have 0 duplicate definitions across src/server')
  const nonKernelSensitiveDups = report.safetyPrimitiveDuplicates.filter(
    d =>
      (d.name === 'isSensitiveRepoEntry' || d.name === 'isSensitiveRepoRelativePath') &&
      d.file !== 'src/server/exec-verify.ts',
  )
  assert.deepEqual(nonKernelSensitiveDups, [], 'non-kernel isSensitiveRepoEntry must have 0 duplicate definitions')

  const cli = runNodeScript('scripts/check-clones.ts', [])
  assert.equal(cli.status, 0, `CLI check-clones failed:\n${cli.stdout}\n${cli.stderr}`)
  assert.match(cli.stdout, /check-clones PASS/)
})

test('R3-10 Step 3: check-clones detects injected cross-file clone (even with renamed locals) and enforces removal-only baseline', t => {
  const root = makeTempDir(t, 'kovo-r3-10-clones-')
  mkdirSync(join(root, 'src', 'server'), { recursive: true })
  mkdirSync(join(root, 'scripts'), { recursive: true })

  writeFileSync(
    join(root, 'src', 'server', 'alpha.ts'),
    [
      'export function computeScore(items: number[]): number {',
      '  let total = 0',
      '  for (const item of items) {',
      '    if (item > 0) {',
      '      total += item * 2',
      '    }',
      '  }',
      '  return total',
      '}',
      '',
    ].join('\n'),
  )
  writeFileSync(join(root, 'src', 'server', 'beta.ts'), 'export const ok = true\n')

  // Bootstrap clean baseline (0 clone groups).
  const boot = runCloneCheck({ rootDir: root, writeBaseline: true, bootstrapSafetyDebt: [] })
  assert.equal(boot.ok, true)
  assert.equal(boot.cloneGroups.length, 0)

  // Inject cross-file clone into beta.ts with renamed locals & added comment -> DETECTED & FAILS!
  writeFileSync(
    join(root, 'src', 'server', 'beta.ts'),
    [
      'export function scoreEntries(nums: number[]): number {',
      '  // renamed locals and comment should still match normalized AST hash',
      '  let acc = 0',
      '  for (const n of nums) {',
      '    if (n > 0) {',
      '      acc += n * 2',
      '    }',
      '  }',
      '  return acc',
      '}',
      '',
    ].join('\n'),
  )

  const detected = runCloneCheck({ rootDir: root })
  assert.equal(detected.ok, false)
  assert.equal(detected.newCloneGroups.length, 1)
  assert.deepEqual(detected.newCloneGroups[0]!.files, ['src/server/alpha.ts', 'src/server/beta.ts'])

  // --write-baseline MUST refuse adding a new clone group to an existing baseline.
  const refuseWrite = runCloneCheck({ rootDir: root, writeBaseline: true })
  assert.equal(refuseWrite.ok, false)
  assert.match(refuseWrite.error ?? '', /removal-only/i)

  // Injecting a duplicate safety primitive fails even if shorter than 6 lines.
  writeFileSync(
    join(root, 'src', 'server', 'beta.ts'),
    'export function constantTimeStringEqual(x: string, y: string): boolean { return x === y }\n',
  )
  const safetyDupFail = runCloneCheck({ rootDir: root })
  assert.equal(safetyDupFail.ok, false)
  assert.equal(safetyDupFail.unticketedSafetyPrimitiveDuplicates.length, 1)
})

// ---------------------------------------------------------------------------
// 4. Consolidated safety-primitives.ts strictest semantics & single-source guard
// ---------------------------------------------------------------------------

test('R3-10 Step 3: safety-primitives.ts preserves strictest isSensitiveRepoEntry, isSensitiveRepoRelativePath, and constantTimeStringEqual semantics', () => {
  // isSensitiveRepoEntry: sensitive dot-dirs including .git (strictest from exec-recon-planner.ts).
  for (const dir of ['.ssh', '.aws', '.gnupg', '.kube', '.docker', '.git', '.SSH', '.GIT']) {
    assert.equal(isSensitiveRepoEntry(dir, dir, true), true, `dir ${dir} must be sensitive`)
  }
  assert.equal(isSensitiveRepoEntry('.git/hooks', 'hooks', true), true)
  assert.equal(isSensitiveRepoEntry('nested/.git/hooks', 'hooks', true), true)
  assert.equal(isSensitiveRepoEntry('.ssh/sub', 'sub', true), true)
  assert.equal(isSensitiveRepoEntry('src/components', 'components', true), false)

  // Sensitive files, keys, .env variants, backslash normalization, and credential dirs.
  assert.equal(isSensitiveRepoEntry('.env', '.env', false), true)
  assert.equal(isSensitiveRepoEntry('.env.production.js', '.env.production.js', false), true)
  assert.equal(isSensitiveRepoEntry('.env.local', '.env.local', false), true)
  assert.equal(isSensitiveRepoEntry('.env.example', '.env.example', false), false)
  assert.equal(isSensitiveRepoEntry('.env.sample', '.env.sample', false), false)
  assert.equal(isSensitiveRepoEntry('.env.template', '.env.template', false), false)
  assert.equal(isSensitiveRepoEntry('.git/config', 'config', false), true)
  assert.equal(isSensitiveRepoEntry('.git\\config', 'config', false), true)
  assert.equal(isSensitiveRepoEntry('.ssh/helper.ts', 'helper.ts', false), true)
  assert.equal(isSensitiveRepoEntry('server.pem', 'server.pem', false), true)
  assert.equal(isSensitiveRepoEntry('heldout.salt', 'heldout.salt', false), true)
  assert.equal(isSensitiveRepoEntry('github.pat', 'github.pat', false), true)
  assert.equal(isSensitiveRepoEntry('secrets.json', 'secrets.json', false), true)
  assert.equal(isSensitiveRepoEntry('credentials/prod.json', 'prod.json', false), true)
  assert.equal(isSensitiveRepoEntry('credentials/loader.ts', 'loader.ts', false), false)
  assert.equal(isSensitiveRepoEntry('src/sibling.ts', 'sibling.ts', false), false)

  // isSensitiveRepoRelativePath: fail-closed on empty, slash-only, null byte, and traversal (strictest).
  assert.equal(isSensitiveRepoRelativePath(''), true)
  assert.equal(isSensitiveRepoRelativePath('///'), true)
  assert.equal(isSensitiveRepoRelativePath('src/\0app.ts'), true)
  assert.equal(isSensitiveRepoRelativePath('../secrets.txt'), true)
  assert.equal(isSensitiveRepoRelativePath('src/../.env'), true)
  assert.equal(isSensitiveRepoRelativePath('.git/HEAD'), true)
  assert.equal(isSensitiveRepoRelativePath('.ssh/id_rsa'), true)
  assert.equal(isSensitiveRepoRelativePath('.env.production.js'), true)
  assert.equal(isSensitiveRepoRelativePath('src/sibling.ts'), false)
  assert.equal(isSensitiveRepoRelativePath('.env.example'), false)

  // constantTimeStringEqual: UTF-8 accuracy, length mismatch, empty strings, and non-string fail-closed.
  assert.equal(constantTimeStringEqual('', ''), true)
  assert.equal(constantTimeStringEqual('kovo_att_deadbeef', 'kovo_att_deadbeef'), true)
  assert.equal(constantTimeStringEqual('café', 'café'), true)
  assert.equal(constantTimeStringEqual('kovo_att_deadbeef', 'kovo_att_deadbeee'), false)
  assert.equal(constantTimeStringEqual('short', 'much-longer'), false)
  assert.equal(constantTimeStringEqual('é', 'e'), false)
  assert.equal(constantTimeStringEqual('é', 'ab'), false)
  assert.equal(constantTimeStringEqual('', 'a'), false)
  assert.equal(constantTimeStringEqual(null as unknown as string, 'a'), false)
  assert.equal(constantTimeStringEqual('a', undefined as unknown as string), false)

  // Verify all 5 consolidated modules delegate to ./safety-primitives.ts with zero local definitions.
  for (const rel of [
    'src/server/exec-recon-planner.ts',
    'src/server/worker-backend.ts',
    'src/server/browser-session-auth.ts',
    'src/server/scoped-browser.ts',
    'src/server/egress-gateway.ts',
  ]) {
    const src = readFileSync(join(REPO_ROOT, rel), 'utf8')
    assert.match(src, /from\s+['"]\.\/safety-primitives\.ts['"]/, `${rel} must import from ./safety-primitives.ts`)
    assert.equal(
      /\bfunction\s+(?:isSensitiveRepoEntry|isSensitiveRepoRelativePath|constantTimeStringEqual)\b/.test(src),
      false,
      `${rel} must not contain a duplicate local safety-primitive definition`,
    )
  }
})
