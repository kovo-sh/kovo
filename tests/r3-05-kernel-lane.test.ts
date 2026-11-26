/**
 * R3-05 fast hermetic guard tests (`plans/claude_quality_3.md` §5):
 *  1. `scripts/check-verdict-flip.ts`:
 *     - catches un-trailered `confirmed: true <-> false` flips in `KERNEL_TEST_RE`, `@kernel`-tagged
 *       test files, and existing `tests/parity/corpus/*.json` files;
 *     - catches un-trailered edits to existing TP/FP fixtures (e.g. status 404 -> 200) while
 *       allowing newly added corpus files and pure trailing-comma additive JSON edits;
 *     - catches `fix(worker-gate)` / `test(worker-gate)` / `fix(gate)` commits touching files
 *       outside `tests/` unless BOTH `Kernel-change:` and `Reviewed-by:` trailers are present;
 *     - passes when proper `Verdict-flip:` / `Kernel-change:` + `Reviewed-by:` trailers exist.
 *  2. `scripts/check-kernel-review.ts`:
 *     - passes cleanly on non-kernel diffs;
 *     - loads `scripts/kernel-manifest.json` when present and falls back to the 20-file kernel set;
 *     - rejects kernel diffs missing `Reviewed-by:`, citing a same-family reviewer, or citing a
 *       missing / non-rejecting (TP) bypass corpus case;
 *     - passes when a different-model `Reviewed-by:` + newly added rejecting FP corpus case
 *       (or `--allow-case-id` / `Expedited-kernel-fix:` override) is present.
 *  3. `scripts/merge-stream.sh` hook & `AGENTS.md` kernel-lane policy.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  FALLBACK_CONFIRMATION_KERNEL_FILES,
  checkKernelReviewRepo,
  evaluateKernelReview,
  extractModelFamily,
  loadConfirmationKernelManifest,
} from '../scripts/check-kernel-review.ts'
import {
  checkVerdictFlipRepo,
  detectVerdictFlips,
  evaluateVerdictFlipCommit,
  isGateRepairSubject,
} from '../scripts/check-verdict-flip.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const CHECK_VERDICT_FLIP_TS = join(REPO_ROOT, 'scripts/check-verdict-flip.ts')
const CHECK_KERNEL_REVIEW_TS = join(REPO_ROOT, 'scripts/check-kernel-review.ts')
const MERGE_STREAM_SH = join(REPO_ROOT, 'scripts/merge-stream.sh')

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function initTempGitRepo(t: { after: (fn: () => void) => void }, prefix: string): {
  repo: string
  git: (...args: string[]) => string
} {
  const repo = makeTempDir(t, prefix)
  const git = (...args: string[]) =>
    execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
  git('init', '-b', 'main')
  git('config', 'user.email', 'r305-test@example.invalid')
  git('config', 'user.name', 'R305 Tester')
  return { repo, git }
}

function makeBypassCorpusJson(id: string, confirmed: boolean, side: 'fp' | 'tp' = confirmed ? 'tp' : 'fp'): string {
  return JSON.stringify(
    {
      id,
      side,
      archetype: 'kernel-bypass-variant',
      description: 'Independent reviewer bypass-variant negative control case.',
      expected: { confirmed },
    },
    null,
    2,
  ) + '\n'
}

// ============================================================================
// 1. scripts/check-verdict-flip.ts — Verdict Flips & Gate-Repair Tests-Only Guard
// ============================================================================

test('R3-05.1: check-verdict-flip catches un-trailered confirmed true->false flips and existing fixture edits, and passes with Verdict-flip trailer', () => {
  const flipDiff = [
    'diff --git a/tests/r3-oracle-invariants.test.ts b/tests/r3-oracle-invariants.test.ts',
    '--- a/tests/r3-oracle-invariants.test.ts',
    '+++ b/tests/r3-oracle-invariants.test.ts',
    '@@ -40,4 +40,4 @@',
    '   const out = assessAuthorizationImpact(input)',
    '-  assert.equal(out.confirmed, true)',
    '+  assert.equal(out.confirmed, false)',
  ].join('\n')

  const hits = detectVerdictFlips(flipDiff)
  assert.equal(hits.length, 1)
  assert.equal(hits[0]!.kind, 'verdict_assertion_flip')

  // Missing trailer -> FAIL
  const failMissing = evaluateVerdictFlipCommit({
    sha: 'deadbeef1234',
    subject: 'fix(oracle): tighten cross-persona check',
    commitMessage: 'fix(oracle): tighten cross-persona check\n',
    diffText: flipDiff,
  })
  assert.equal(failMissing.ok, false)
  assert.equal(failMissing.violations.length, 1)

  // Malformed trailer (missing reason) -> FAIL
  const failMalformed = evaluateVerdictFlipCommit({
    sha: 'deadbeef1234',
    subject: 'fix(oracle): tighten cross-persona check',
    commitMessage: 'fix(oracle): tighten cross-persona check\n\nVerdict-flip: r3-c5\n',
    diffText: flipDiff,
  })
  assert.equal(failMalformed.ok, false)

  // Valid Verdict-flip trailer -> PASS
  const passTrail = evaluateVerdictFlipCommit({
    sha: 'deadbeef1234',
    subject: 'fix(oracle): tighten cross-persona check',
    commitMessage:
      'fix(oracle): tighten cross-persona check\n\nVerdict-flip: r3-c5-cross-persona-replay previous TP encoded FP cross-persona replay\n',
    diffText: flipDiff,
  })
  assert.equal(passTrail.ok, true)
  assert.equal(passTrail.verdictFlipTrailers.length, 1)

  // Existing TP fixture edit (status 404 -> 200) inside @kernel-tagged non-KERNEL_TEST_RE suite -> caught!
  const fixtureEditDiff = [
    'diff --git a/tests/r4-host-compute.test.ts b/tests/r4-host-compute.test.ts',
    '--- a/tests/r4-host-compute.test.ts',
    '+++ b/tests/r4-host-compute.test.ts',
    '@@ -12,4 +12,4 @@',
    '   const probe = {',
    '-    status: 404,',
    '+    status: 200,',
    '     body: "ok",',
  ].join('\n')
  const taggedHits = detectVerdictFlips(fixtureEditDiff, {
    taggedKernelFiles: new Set(['tests/r4-host-compute.test.ts']),
  })
  assert.equal(taggedHits.length, 1)
  assert.equal(taggedHits[0]!.kind, 'kernel_fixture_edit')

  // Purely additive new corpus file MUST NOT be flagged as a verdict flip!
  const newCorpusDiff = [
    'diff --git a/tests/parity/corpus/r3-05-new-bypass-fp.json b/tests/parity/corpus/r3-05-new-bypass-fp.json',
    'new file mode 100644',
    '--- /dev/null',
    '+++ b/tests/parity/corpus/r3-05-new-bypass-fp.json',
    '@@ -0,0 +1,5 @@',
    '+{',
    '+  "id": "r3-05-new-bypass-fp",',
    '+  "side": "fp",',
    '+  "expected": { "confirmed": false }',
    '+}',
  ].join('\n')
  assert.equal(detectVerdictFlips(newCorpusDiff).length, 0)

  // Purely additive trailing-comma JSON edit (e.g. adding covers metadata) MUST NOT be flagged!
  const additiveCorpusDiff = [
    'diff --git a/tests/parity/corpus/bfla-vertical-tp.json b/tests/parity/corpus/bfla-vertical-tp.json',
    '--- a/tests/parity/corpus/bfla-vertical-tp.json',
    '+++ b/tests/parity/corpus/bfla-vertical-tp.json',
    '@@ -10,2 +10,5 @@',
    '-  "expected": { "confirmed": true }',
    '+  "expected": { "confirmed": true },',
    '+  "covers": { "files": ["src/server/oracle-invariants.ts"], "classes": ["bfla"] }',
  ].join('\n')
  assert.equal(detectVerdictFlips(additiveCorpusDiff).length, 0)

  // Flipping confirmed inside an existing corpus file MUST be flagged!
  const corpusFlipDiff = [
    'diff --git a/tests/parity/corpus/bfla-vertical-tp.json b/tests/parity/corpus/bfla-vertical-tp.json',
    '--- a/tests/parity/corpus/bfla-vertical-tp.json',
    '+++ b/tests/parity/corpus/bfla-vertical-tp.json',
    '@@ -10,2 +10,2 @@',
    '-  "confirmed": true',
    '+  "confirmed": false',
  ].join('\n')
  const corpusHits = detectVerdictFlips(corpusFlipDiff)
  assert.equal(corpusHits.length, 1)
  assert.equal(corpusHits[0]!.kind, 'corpus_verdict_flip')
})

test('R3-05.2: check-verdict-flip blocks fix(worker-gate)/test(worker-gate)/fix(gate) editing src/server/oracle-invariants.ts unless Kernel-change + Reviewed-by trailers exist', (t) => {
  assert.equal(isGateRepairSubject('fix(worker-gate): repair oracle'), true)
  assert.equal(isGateRepairSubject('test(worker-gate): adjust flake'), true)
  assert.equal(isGateRepairSubject('fix(gate): unblock merge'), true)
  assert.equal(isGateRepairSubject('fix(oracle): tighten guard'), false)

  const { repo, git } = initTempGitRepo(t, 'r305-gate-repair-')
  mkdirSync(join(repo, 'src/server'), { recursive: true })
  mkdirSync(join(repo, 'tests'), { recursive: true })
  writeFileSync(join(repo, 'src/server/oracle-invariants.ts'), 'export const strict = true\n')
  writeFileSync(join(repo, 'tests/r3-oracle-invariants.test.ts'), 'assert.equal(res.confirmed, true)\n')
  git('add', '.')
  git('commit', '-m', 'init')

  // 2a. fix(worker-gate) editing src/server/oracle-invariants.ts WITHOUT Kernel-change + Reviewed-by -> FAIL!
  writeFileSync(join(repo, 'src/server/oracle-invariants.ts'), 'export const strict = false\n')
  git('add', 'src/server/oracle-invariants.ts')
  git('commit', '-m', 'fix(worker-gate): loosen oracle check to pass suite')

  const failCli = spawnSync(
    process.execPath,
    [CHECK_VERDICT_FLIP_TS, '--root', repo, '--base', 'HEAD~1'],
    { encoding: 'utf8' },
  )
  assert.equal(failCli.status, 1, 'fix(worker-gate) editing src/ without trailers must FAIL')
  assert.match(failCli.stderr, /Kernel-change/)
  assert.match(failCli.stderr, /Reviewed-by/)

  // 2b. Only Kernel-change (still missing Reviewed-by) -> STILL FAIL!
  git('commit', '--amend', '-m', 'fix(worker-gate): loosen oracle\n\nKernel-change: tightening boundary')
  const failHalf = checkVerdictFlipRepo({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(failHalf.ok, false)
  assert.deepEqual(failHalf.commits[0]!.gateRepairViolation?.missingTrailers, ['Reviewed-by'])

  // 2c. BOTH Kernel-change AND Reviewed-by -> PASS!
  git(
    'commit',
    '--amend',
    '-m',
    [
      'fix(worker-gate): adjust oracle with full review',
      '',
      'Kernel-change: tightening boundary rule',
      'Reviewed-by: claude-opus-4 r3-05-bypass-fp',
    ].join('\n'),
  )
  const passBoth = spawnSync(
    process.execPath,
    [CHECK_VERDICT_FLIP_TS, '--root', repo, '--base', 'HEAD~1', '--json'],
    { encoding: 'utf8' },
  )
  assert.equal(passBoth.status, 0, `expected PASS with both trailers: ${passBoth.stderr}`)
  assert.equal((JSON.parse(passBoth.stdout) as { ok: boolean }).ok, true)

  // 2d. fix(worker-gate) touching ONLY tests/ (non-flip test edit) -> PASS!
  writeFileSync(join(repo, 'tests/helper.test.ts'), 'export const ok = true\n')
  git('add', 'tests/helper.test.ts')
  git('commit', '-m', 'test(worker-gate): add tests-only helper')
  const passTestsOnly = checkVerdictFlipRepo({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(passTestsOnly.ok, true)
})

// ============================================================================
// 2. scripts/check-kernel-review.ts — Different-Model Kernel Review Lane
// ============================================================================

test('R3-05.3: check-kernel-review passes on non-kernel diffs, enforces different-model reviewer + rejecting FP bypass case, and honors Expedited-kernel-fix override', (t) => {
  // Confirm 20-file canonical fallback list includes the R3-04 additions.
  assert.equal(FALLBACK_CONFIRMATION_KERNEL_FILES.length, 20)
  assert.ok(FALLBACK_CONFIRMATION_KERNEL_FILES.includes('src/server/terminal-oracle-registry.ts'))
  assert.ok(FALLBACK_CONFIRMATION_KERNEL_FILES.includes('src/server/verify-prove-handlers.ts'))
  assert.ok(FALLBACK_CONFIRMATION_KERNEL_FILES.includes('src/server/composite-autodag.ts'))

  // Model family classification
  assert.equal(extractModelFamily('claude-opus-4-6'), 'anthropic-claude')
  assert.equal(extractModelFamily('claude-sonnet-4'), 'anthropic-claude')
  assert.equal(extractModelFamily('google/gemini-2.5-pro'), 'google-gemini')
  assert.equal(extractModelFamily('opencode-glm-5'), 'zhipu-glm')
  assert.equal(extractModelFamily('self'), 'invalid')

  // 3a. Non-kernel diff -> PASS (not required)
  const nonKernel = evaluateKernelReview({
    changedFiles: ['src/server/broker.ts', 'tests/broker.test.ts'],
    commitMessages: 'refactor(broker): tidy logging\n',
  })
  assert.equal(nonKernel.ok, true)
  assert.equal(nonKernel.required, false)

  // 3b. Kernel diff missing Reviewed-by -> FAIL
  const missingReview = evaluateKernelReview({
    changedFiles: ['src/server/oracle-invariants.ts'],
    commitMessages: 'fix(oracle): add boundary guard\n',
  })
  assert.equal(missingReview.ok, false)
  assert.equal(missingReview.required, true)
  assert.match(missingReview.violations[0] ?? '', /Reviewed-by/)

  // 3c. Kernel diff citing SAME model family -> FAIL
  const corpusFpPath = 'tests/parity/corpus/r3-05-bypass-fp.json'
  const corpusFpMap = new Map([[corpusFpPath, makeBypassCorpusJson('r3-05-bypass-fp', false, 'fp')]])
  const sameFamily = evaluateKernelReview({
    changedFiles: ['src/server/oracle-invariants.ts', corpusFpPath],
    addedOrModifiedCorpusFiles: [corpusFpPath],
    corpusFileContents: corpusFpMap,
    commitMessages: [
      'fix(oracle): add boundary guard',
      '',
      'Author-model: gemini-2.5-pro',
      'Reviewed-by: gemini-2.5-flash r3-05-bypass-fp',
    ].join('\n'),
  })
  assert.equal(sameFamily.ok, false)
  assert.match(sameFamily.violations[0] ?? '', /Same-family review rejected/)

  // 3d. Kernel diff with different-model reviewer BUT missing bypass corpus file in diff -> FAIL
  const missingBypassCase = evaluateKernelReview({
    changedFiles: ['src/server/oracle-invariants.ts'],
    addedOrModifiedCorpusFiles: [],
    commitMessages: [
      'fix(oracle): add boundary guard',
      '',
      'Author-model: gemini-2.5-pro',
      'Reviewed-by: claude-opus-4 r3-05-missing-fp',
    ].join('\n'),
  })
  assert.equal(missingBypassCase.ok, false)
  assert.match(missingBypassCase.violations[0] ?? '', /not found among newly added\/updated rejecting FP corpus cases/)

  // 3e. Kernel diff citing a TP (expected.confirmed === true) corpus case -> FAIL
  const corpusTpPath = 'tests/parity/corpus/r3-05-not-rejecting-tp.json'
  const corpusTpMap = new Map([[corpusTpPath, makeBypassCorpusJson('r3-05-not-rejecting-tp', true, 'tp')]])
  const nonRejectingCase = evaluateKernelReview({
    changedFiles: ['src/server/oracle-invariants.ts', corpusTpPath],
    addedOrModifiedCorpusFiles: [corpusTpPath],
    corpusFileContents: corpusTpMap,
    commitMessages: [
      'fix(oracle): add boundary guard',
      '',
      'Author-model: gemini-2.5-pro',
      'Reviewed-by: claude-opus-4 r3-05-not-rejecting-tp',
    ].join('\n'),
  })
  assert.equal(nonRejectingCase.ok, false)
  assert.match(nonRejectingCase.violations[0] ?? '', /rejecting case/)

  // 3f. Different-model reviewer + newly added rejecting FP corpus case -> PASS!
  const validReview = evaluateKernelReview({
    changedFiles: ['src/server/oracle-invariants.ts', corpusFpPath],
    addedOrModifiedCorpusFiles: [corpusFpPath],
    corpusFileContents: corpusFpMap,
    commitMessages: [
      'fix(oracle): add boundary guard',
      '',
      'Author-model: gemini-2.5-pro',
      'Reviewed-by: claude-opus-4 r3-05-bypass-fp',
    ].join('\n'),
  })
  assert.equal(validReview.ok, true)
  assert.equal(validReview.acceptedReview?.reviewerFamily, 'anthropic-claude')
  assert.equal(validReview.bypassCase?.expectedConfirmed, false)

  // 3g. Operator-signed Expedited-kernel-fix override -> PASS (and malformed override -> FAIL)
  const expeditedPass = evaluateKernelReview({
    changedFiles: ['src/server/terminal-oracle-registry.ts'],
    commitMessages: [
      'fix(security): emergency bypass patch',
      '',
      'Expedited-kernel-fix: operator:secops critical production bypass; independent review due within 24h',
    ].join('\n'),
  })
  assert.equal(expeditedPass.ok, true)
  assert.equal(expeditedPass.expeditedOverride?.operatorId, 'operator:secops')

  const expeditedMalformed = evaluateKernelReview({
    changedFiles: ['src/server/terminal-oracle-registry.ts'],
    commitMessages: 'fix(security): emergency\n\nExpedited-kernel-fix: secops\n',
  })
  assert.equal(expeditedMalformed.ok, false)

  // 3h. Manifest loader reads scripts/kernel-manifest.json when present!
  const manifestDir = makeTempDir(t, 'r305-manifest-')
  mkdirSync(join(manifestDir, 'scripts'), { recursive: true })
  writeFileSync(
    join(manifestDir, 'scripts/kernel-manifest.json'),
    JSON.stringify({ version: 1, files: ['src/server/custom-kernel-oracle.ts'] }),
  )
  const loaded = loadConfirmationKernelManifest(manifestDir)
  assert.equal(loaded.source, 'scripts/kernel-manifest.json')
  assert.equal(loaded.files.has('src/server/custom-kernel-oracle.ts'), true)

  const manifestProtected = evaluateKernelReview({
    rootDir: manifestDir,
    changedFiles: ['src/server/custom-kernel-oracle.ts'],
    commitMessages: 'feat(kernel): touch manifest file without review\n',
  })
  assert.equal(manifestProtected.ok, false)
  assert.equal(manifestProtected.manifestSource, 'scripts/kernel-manifest.json')
})

test('R3-05.4: check-kernel-review CLI supports --allow-case-id and git repo checks', (t) => {
  const { repo, git } = initTempGitRepo(t, 'r305-kr-cli-')
  mkdirSync(join(repo, 'src/server'), { recursive: true })
  writeFileSync(join(repo, 'src/server/oracle-invariants.ts'), 'export const v = 1\n')
  git('add', '.')
  git('commit', '-m', 'init')

  writeFileSync(join(repo, 'src/server/oracle-invariants.ts'), 'export const v = 2\n')
  git('add', 'src/server/oracle-invariants.ts')
  git(
    'commit',
    '-m',
    [
      'fix(oracle): tighten guard',
      '',
      'Author-model: gemini-2.5-pro',
      'Reviewed-by: opencode-glm-5 unit-test-bypass-fp',
    ].join('\n'),
  )

  // Without --allow-case-id and without corpus file in diff -> FAIL
  const failRes = checkKernelReviewRepo({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(failRes.ok, false)

  // With --allow-case-id unit-test-bypass-fp -> PASS
  const passCli = spawnSync(
    process.execPath,
    [CHECK_KERNEL_REVIEW_TS, '--root', repo, '--base', 'HEAD~1', '--allow-case-id', 'unit-test-bypass-fp', '--json'],
    { encoding: 'utf8' },
  )
  assert.equal(passCli.status, 0, `expected --allow-case-id PASS: ${passCli.stderr}`)
  const parsed = JSON.parse(passCli.stdout) as { ok: boolean; bypassCase: { viaAllowList: boolean } }
  assert.equal(parsed.ok, true)
  assert.equal(parsed.bypassCase.viaAllowList, true)
})

// ============================================================================
// 3. scripts/merge-stream.sh kernel-review hook & AGENTS.md policy guard
// ============================================================================

test('R3-05.5: merge-stream.sh blocks unreviewed confirmation-kernel branch, passes reviewed kernel branch, and respects --skip-kernel-review', (t) => {
  const { repo, git } = initTempGitRepo(t, 'r305-merge-hook-')
  const stateDir = makeTempDir(t, 'r305-merge-state-')

  mkdirSync(join(repo, 'src/server'), { recursive: true })
  mkdirSync(join(repo, 'tests/parity/corpus'), { recursive: true })
  writeFileSync(join(repo, 'src/server/oracle-invariants.ts'), 'export const ruleVersion = 1\n')
  git('add', '.')
  git('commit', '-m', 'initial main')
  const baseSha = git('rev-parse', 'main')

  // Branch A: unreviewed confirmation-kernel change -> MUST be blocked by merge-stream.sh!
  git('checkout', '-b', 'feat/unreviewed-kernel')
  writeFileSync(join(repo, 'src/server/oracle-invariants.ts'), 'export const ruleVersion = 2\n')
  git('add', 'src/server/oracle-invariants.ts')
  git('commit', '-m', 'fix(oracle): unreviewed kernel edit')

  // Branch B: properly reviewed confirmation-kernel change + rejecting FP bypass case -> MUST PASS!
  git('checkout', '-b', 'feat/reviewed-kernel', 'main')
  writeFileSync(join(repo, 'src/server/oracle-invariants.ts'), 'export const ruleVersion = 3\n')
  writeFileSync(
    join(repo, 'tests/parity/corpus/r3-05-merge-bypass-fp.json'),
    makeBypassCorpusJson('r3-05-merge-bypass-fp', false, 'fp'),
  )
  git('add', '.')
  git(
    'commit',
    '-m',
    [
      'fix(oracle): reviewed kernel edit with bypass case',
      '',
      'Author-model: gemini-2.5-pro',
      'Reviewed-by: claude-opus-4 r3-05-merge-bypass-fp',
    ].join('\n'),
  )
  const reviewedSha = git('rev-parse', 'HEAD')
  git('checkout', 'main')

  const runMerge = (args: string[]) =>
    spawnSync('bash', [MERGE_STREAM_SH, ...args], {
      cwd: repo,
      env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir },
      encoding: 'utf8',
    })

  // 5a. Unreviewed kernel branch is blocked before fast-forwarding main!
  const blockedRes = runMerge(['feat/unreviewed-kernel', '--base', 'main', '--skip-ci-check', '--gate-cmd', 'true', '--json'])
  assert.notEqual(blockedRes.status, 0, 'unreviewed kernel branch must fail merge-stream.sh')
  const blockedJson = JSON.parse(blockedRes.stdout) as { ok: boolean; status: string }
  assert.equal(blockedJson.ok, false)
  assert.equal(blockedJson.status, 'KERNEL_REVIEW_FAILED')
  assert.equal(git('rev-parse', 'main'), baseSha, 'main MUST stay untouched when kernel review fails')

  // 5b. --skip-kernel-review escape hatch (for unit tests) allows dry-run to pass cleanly.
  const skippedDryRes = runMerge([
    'feat/unreviewed-kernel',
    '--base', 'main',
    '--dry-run',
    '--skip-ci-check',
    '--skip-kernel-review',
    '--gate-cmd', 'true',
    '--json',
  ])
  assert.equal(skippedDryRes.status, 0, `--skip-kernel-review dry-run failed: ${skippedDryRes.stderr}`)
  assert.equal(git('rev-parse', 'main'), baseSha)

  // 5c. Properly reviewed kernel branch with different-model Reviewed-by + rejecting FP bypass case PASSES and fast-forwards main!
  const passRes = runMerge(['feat/reviewed-kernel', '--base', 'main', '--skip-ci-check', '--gate-cmd', 'true', '--json'])
  assert.equal(passRes.status, 0, `reviewed kernel branch should pass merge-stream.sh: ${passRes.stderr}`)
  const passJson = JSON.parse(passRes.stdout) as { ok: boolean; status: string; newSha: string }
  assert.equal(passJson.ok, true)
  assert.equal(passJson.status, 'PASS')
  assert.equal(passJson.newSha, reviewedSha)
  assert.equal(git('rev-parse', 'main'), reviewedSha)
})

test('R3-05.6: AGENTS.md documents Independent kernel review lane (R3-05) policy invariants', () => {
  const agentsMd = readFileSync(join(REPO_ROOT, 'AGENTS.md'), 'utf8')
  assert.match(agentsMd, /## Independent kernel review lane \(R3-05\)/)
  assert.match(agentsMd, /ACTION MERGE NOW/)
  assert.match(agentsMd, /different model family/i)
  assert.match(agentsMd, /raw diff/i)
  assert.match(agentsMd, /Verdict-flip:/)
  assert.match(agentsMd, /Expedited-kernel-fix:/)
})
