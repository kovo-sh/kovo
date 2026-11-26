// @kernel @fixes R3-04
/**
 * R3-04 regression & history-replay test suite (`plans/claude_quality_3.md` §4):
 *  1. Complete confirmation-kernel file set (all 7 newly added files + retest-health) and
 *     TypeScript AST export-staleness test over `src/server/*.ts`.
 *  2. Generated `scripts/kernel-manifest.json` freshness (`scripts/gen-kernel-manifest.ts --check`)
 *     and drift detection on synthetic repos.
 *  3. Parity corpus `covers: { files[], classes[] }` completeness across all 40 cases.
 *  4. Real git history-replay guard: `13337ae`, `fafeb3c`, and `8a94536` MUST ALL FAIL.
 *  5. Per-commit `Parity-case` binding (no range-wide laundering), `Kernel-change: loosening`
 *     (TP + FP required + optional `Reviewed-by:`), and audited `Kernel-gate-override:`.
 *  6. Semantic `// @kernel` and `// @fixes <ID>` test tag protection across all 14 `r4-*.test.ts`
 *     suites and arbitrary non-prefixed test filenames.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  checkGitRepo,
  detectContractChanges,
  evaluateContractChange,
  evaluateParityGate,
  evaluateSingleCommitParityGate,
  formatContractChangeReport,
  isConfirmationKernelFile,
  isGateOrKernelTestFile,
  loadKernelManifestFiles,
  loadParityCorpusCases,
} from '../scripts/check-contract-change.ts'
import {
  checkKernelManifestFreshness,
  generateKernelManifest,
  scanKernelExportFiles,
  serializeKernelManifest,
} from '../scripts/gen-kernel-manifest.ts'
import { hasProtectedTestTag, parseTestFileTags, readTestFileTags } from '../scripts/test-tiers.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const GEN_MANIFEST_TS = join(REPO_ROOT, 'scripts/gen-kernel-manifest.ts')
const CHECK_CONTRACT_TS = join(REPO_ROOT, 'scripts/check-contract-change.ts')

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeTempGitRepo(t: { after: (fn: () => void) => void }, prefix: string): {
  repo: string
  git: (...args: string[]) => string
} {
  const repo = makeTempDir(t, prefix)
  const git = (...args: string[]) =>
    execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
  git('init', '-b', 'main')
  git('config', 'user.email', 'r304-test@example.invalid')
  git('config', 'user.name', 'R304 Tester')
  return { repo, git }
}

// ============================================================================
// 1. Complete kernel file set + export staleness + manifest freshness
// ============================================================================

test('R3-04: isConfirmationKernelFile and kernel-manifest.json include all 7 previously missing kernel files', () => {
  const sevenMissingFiles = [
    'src/server/terminal-oracle-registry.ts',
    'src/server/verify-prove-handlers.ts',
    'src/server/verify-rpc.ts',
    'src/server/agent-script-proof.ts',
    'src/server/host-fact-log.ts',
    'src/server/causal-proof-compiler.ts',
    'src/server/composite-autodag.ts',
  ]
  const manifestFiles = loadKernelManifestFiles(REPO_ROOT)
  assert.ok(manifestFiles, 'scripts/kernel-manifest.json must exist and load cleanly')

  for (const file of sevenMissingFiles) {
    assert.equal(isConfirmationKernelFile(file), true, `isConfirmationKernelFile must gate ${file}`)
    assert.equal(manifestFiles.has(file), true, `scripts/kernel-manifest.json must include ${file}`)
  }

  // Non-kernel server files stay excluded.
  assert.equal(isConfirmationKernelFile('src/server/ui-server.ts'), false)
  assert.equal(isConfirmationKernelFile('src/server/safe-regex.ts'), false)
  assert.equal(isConfirmationKernelFile('src/server/store.ts'), false)
})

test('R3-04 export staleness: every src/server/*.ts exporting assess*, verify*Receipt, or evaluate*Oracle is gated', () => {
  const manifestFiles = loadKernelManifestFiles(REPO_ROOT)
  assert.ok(manifestFiles, 'scripts/kernel-manifest.json must exist')

  const exportedKernelFiles = scanKernelExportFiles(REPO_ROOT)
  assert.ok(exportedKernelFiles.size >= 8, `expected >= 8 server files with kernel export signatures, found ${exportedKernelFiles.size}`)

  const missingFromGate: string[] = []
  const missingFromManifest: string[] = []
  for (const [relFile, symbols] of exportedKernelFiles) {
    if (!isConfirmationKernelFile(relFile, REPO_ROOT)) {
      missingFromGate.push(`${relFile} (${symbols.join(', ')})`)
    }
    if (!manifestFiles.has(relFile)) {
      missingFromManifest.push(`${relFile} (${symbols.join(', ')})`)
    }
  }
  assert.deepEqual(missingFromGate, [], `ungated kernel-exporting files: ${missingFromGate.join('; ')}`)
  assert.deepEqual(missingFromManifest, [], `manifest-missing kernel-exporting files: ${missingFromManifest.join('; ')}`)
})

test('R3-04 manifest freshness: scripts/kernel-manifest.json matches ts.Program output and fails when stale', (t) => {
  const freshness = checkKernelManifestFreshness(REPO_ROOT)
  assert.equal(freshness.ok, true, `scripts/kernel-manifest.json is stale: added=${freshness.addedFiles.join(',')} removed=${freshness.removedFiles.join(',')}`)
  assert.equal(freshness.missingFromDisk, false)
  assert.deepEqual(freshness.addedFiles, [])
  assert.deepEqual(freshness.removedFiles, [])

  const cliPass = spawnSync(process.execPath, [GEN_MANIFEST_TS, '--check'], { encoding: 'utf8' })
  assert.equal(cliPass.status, 0, `gen-kernel-manifest.ts --check failed: ${cliPass.stderr}`)
  assert.ok(cliPass.stdout.includes('PASS'))

  // Synthetic repo: adding a new file exporting `assessSyntheticOracle` makes a prior manifest stale.
  const dir = makeTempDir(t, 'r304-manifest-')
  mkdirSync(join(dir, 'src/server'), { recursive: true })
  mkdirSync(join(dir, 'scripts'), { recursive: true })
  writeFileSync(
    join(dir, 'src/server/proof-receipt.ts'),
    "import { helperCheck } from './receipt-helper.ts'\nexport function verifyReceipt(): boolean { return helperCheck() }\n",
  )
  writeFileSync(
    join(dir, 'src/server/receipt-helper.ts'),
    'export function helperCheck(): boolean { return true }\n',
  )

  const initial = generateKernelManifest(dir)
  assert.deepEqual(initial.files, ['src/server/proof-receipt.ts', 'src/server/receipt-helper.ts'])
  writeFileSync(join(dir, 'scripts/kernel-manifest.json'), serializeKernelManifest(initial))
  assert.equal(checkKernelManifestFreshness(dir).ok, true)
  // Custom manifest is consumed by isConfirmationKernelFile(file, dir).
  assert.equal(isConfirmationKernelFile('src/server/receipt-helper.ts', dir), true)

  // Introduce a new oracle-exporting file without regenerating the manifest -> staleness check MUST FAIL!
  writeFileSync(
    join(dir, 'src/server/new-oracle.ts'),
    'export function assessSyntheticOracle(): boolean { return false }\n',
  )
  const stale = checkKernelManifestFreshness(dir)
  assert.equal(stale.ok, false, 'adding an assess* file without regenerating manifest must fail freshness')
  assert.deepEqual(stale.addedFiles, ['src/server/new-oracle.ts'])

  const cliFail = spawnSync(process.execPath, [GEN_MANIFEST_TS, '--check', '--root', dir], { encoding: 'utf8' })
  assert.equal(cliFail.status, 1)
  assert.ok(cliFail.stderr.includes('src/server/new-oracle.ts'))
})

// ============================================================================
// 2. Parity corpus covers metadata completeness
// ============================================================================

test('R3-04 corpus covers: all 40 corpus files declare valid covers.files/classes covering every manifest file', () => {
  const manifestFiles = loadKernelManifestFiles(REPO_ROOT)
  assert.ok(manifestFiles)

  const cases = loadParityCorpusCases(REPO_ROOT)
  assert.ok(cases.size >= 40, `expected >= 40 parity corpus cases, found ${cases.size}`)

  const coveredKernelFiles = new Set<string>()
  for (const [id, meta] of cases) {
    assert.ok(meta.covers, `corpus case ${id} must declare covers: { files, classes }`)
    assert.ok(meta.covers.files.length > 0, `corpus case ${id} must declare non-empty covers.files`)
    assert.ok(meta.covers.classes.length > 0, `corpus case ${id} must declare non-empty covers.classes`)
    for (const f of meta.covers.files) {
      assert.ok(manifestFiles.has(f), `corpus case ${id} covers.files entry "${f}" is not in scripts/kernel-manifest.json`)
      coveredKernelFiles.add(f)
    }
  }

  const uncoveredInCorpus = [...manifestFiles].filter(f => !coveredKernelFiles.has(f)).sort()
  assert.deepEqual(uncoveredInCorpus, [], `kernel manifest files with zero corpus covers: ${uncoveredInCorpus.join(', ')}`)
})

// ============================================================================
// 3. History-replay guard on 13337ae, fafeb3c, and 8a94536
// ============================================================================

test('R3-04 history-replay: commits 13337ae, fafeb3c, and 8a94536 ALL FAIL the upgraded parity gate', () => {
  // 1) 13337ae: exec-verify.ts kernel diff with no corpus touch and no Parity-case trailer.
  const res13337ae = evaluateSingleCommitParityGate(REPO_ROOT, '13337ae')
  assert.equal(res13337ae.required, true, '13337ae must trigger the confirmation-kernel gate')
  assert.equal(res13337ae.ok, false, '13337ae MUST FAIL (missing Parity-case for exec-verify.ts)')
  assert.ok(res13337ae.kernelFilesTouched.includes('src/server/exec-verify.ts'))
  assert.ok(res13337ae.uncoveredKernelFiles.includes('src/server/exec-verify.ts'))

  // 2) fafeb3c: floor-recipe-engine + oracle-invariants + replay-verifier citing unrelated r4-h5-h6-rbac-fp.
  const resFafeb3c = evaluateSingleCommitParityGate(REPO_ROOT, 'fafeb3c')
  assert.equal(resFafeb3c.required, true, 'fafeb3c must trigger the confirmation-kernel gate')
  assert.equal(resFafeb3c.ok, false, 'fafeb3c MUST FAIL (cited r4-h5-h6-rbac-fp does not cover changed files)')
  assert.ok(resFafeb3c.uncoveredKernelFiles.includes('src/server/floor-recipe-engine.ts'))
  assert.ok(resFafeb3c.uncoveredKernelFiles.includes('src/server/oracle-invariants.ts'))
  assert.ok(resFafeb3c.uncoveredKernelFiles.includes('src/server/replay-verifier.ts'))

  // 3) 8a94536: composite-receipt + exec-verify + oracle-invariants + verify-rpc citing only r4-h5-h6-rbac-fp.
  const res8a94536 = evaluateSingleCommitParityGate(REPO_ROOT, '8a94536')
  assert.equal(res8a94536.required, true, '8a94536 must trigger the confirmation-kernel gate')
  assert.equal(res8a94536.ok, false, '8a94536 MUST FAIL (r4-h5-h6-rbac-fp does not cover exec-verify, oracle-invariants, or verify-rpc)')
  assert.ok(res8a94536.kernelFilesTouched.includes('src/server/verify-rpc.ts'))
  assert.ok(res8a94536.uncoveredKernelFiles.includes('src/server/verify-rpc.ts'))
  assert.ok(res8a94536.uncoveredKernelFiles.includes('src/server/exec-verify.ts'))
  assert.ok(res8a94536.uncoveredKernelFiles.includes('src/server/oracle-invariants.ts'))
})

// ============================================================================
// 4. Per-commit binding, loosening (TP+FP), Reviewed-by, and override trailer
// ============================================================================

test('R3-04 per-commit Parity-case binding prevents range-wide trailer laundering in git repos', (t) => {
  const { repo, git } = makeTempGitRepo(t, 'r304-percommit-')
  mkdirSync(join(repo, 'src/server'), { recursive: true })
  mkdirSync(join(repo, 'tests/parity/corpus'), { recursive: true })

  writeFileSync(join(repo, 'src/server/proof-receipt.ts'), 'export const v = 1\n')
  writeFileSync(join(repo, 'src/server/verify-rpc.ts'), 'export const r = 1\n')
  writeFileSync(
    join(repo, 'tests/parity/corpus/receipt-tp.json'),
    JSON.stringify({
      id: 'receipt-tp',
      side: 'tp',
      covers: { files: ['src/server/proof-receipt.ts'], classes: ['bola'] },
    }) + '\n',
  )
  writeFileSync(
    join(repo, 'tests/parity/corpus/rpc-fp.json'),
    JSON.stringify({
      id: 'rpc-fp',
      side: 'fp',
      covers: { files: ['src/server/verify-rpc.ts'], classes: ['auth_bypass'] },
    }) + '\n',
  )
  git('add', '.')
  git('commit', '-m', 'init')
  const baseSha = git('rev-parse', 'HEAD')

  // Commit 1 edits proof-receipt.ts WITHOUT a Parity-case trailer.
  writeFileSync(join(repo, 'src/server/proof-receipt.ts'), 'export const v = 2\n')
  git('add', 'src/server/proof-receipt.ts')
  git('commit', '-m', 'uncovered kernel commit 1')

  // Commit 2 touches verify-rpc.ts AND cites BOTH receipt-tp and rpc-fp.
  // Under range-wide evaluation this would falsely PASS; per-commit evaluation MUST FAIL commit 1!
  writeFileSync(join(repo, 'src/server/verify-rpc.ts'), 'export const r = 2\n')
  git('add', 'src/server/verify-rpc.ts')
  git('commit', '-m', 'commit 2 tries to launder commit 1\n\nParity-case: receipt-tp\nParity-case: rpc-fp')

  const launderRes = checkGitRepo({ rootDir: repo, baseRef: baseSha })
  assert.equal(launderRes.ok, false, 'later commit Parity-case must NOT launder an earlier uncovered kernel commit')
  assert.equal(launderRes.committed.parity?.ok, false)
  assert.equal(launderRes.committed.parity?.commitResults?.length, 2)
  assert.equal(launderRes.committed.parity?.commitResults?.[0]?.ok, false)
  assert.equal(launderRes.committed.parity?.commitResults?.[1]?.ok, true)

  // Reset and verify unrelated Parity-case fails while covering Parity-case passes.
  git('reset', '--hard', baseSha)
  writeFileSync(join(repo, 'src/server/proof-receipt.ts'), 'export const v = 3\n')
  git('add', 'src/server/proof-receipt.ts')
  git('commit', '-m', 'wrong case\n\nParity-case: rpc-fp')

  const wrongCaseRes = checkGitRepo({ rootDir: repo, baseRef: baseSha })
  assert.equal(wrongCaseRes.ok, false, 'unrelated Parity-case (rpc-fp for proof-receipt.ts) must FAIL')
  assert.deepEqual(wrongCaseRes.committed.parity?.uncoveredKernelFiles, ['src/server/proof-receipt.ts'])

  git('commit', '--amend', '-m', 'right case\n\nParity-case: receipt-tp')
  const rightCaseRes = checkGitRepo({ rootDir: repo, baseRef: baseSha })
  assert.equal(rightCaseRes.ok, true, `covering Parity-case must PASS: ${rightCaseRes.committed.parity?.reason}`)
})

test('R3-04 Kernel-change: loosening requires BOTH TP and FP cases, supports Reviewed-by, and supports audited Kernel-gate-override', () => {
  const diff = [
    'diff --git a/src/server/oracle-invariants.ts b/src/server/oracle-invariants.ts',
    '--- a/src/server/oracle-invariants.ts',
    '+++ b/src/server/oracle-invariants.ts',
    '@@ -10,3 +10,3 @@',
    '-  return false',
    '+  return true',
  ].join('\n')

  // Loosening with ONLY a TP case -> FAIL (missing FP).
  const onlyTp = evaluateParityGate({
    diffText: diff,
    commitMessages: 'feat(oracle): loosen check\n\nKernel-change: loosening allow readback diff\nParity-case: cross-tenant-bola-tp\n',
    mode: 'strict',
    rootDir: REPO_ROOT,
  })
  assert.equal(onlyTp.ok, false)
  assert.equal(onlyTp.loosening, true)
  assert.deepEqual(onlyTp.missingLooseningSides, [{ file: 'src/server/oracle-invariants.ts', missing: ['fp'] }])

  // Loosening with ONLY an FP case -> FAIL (missing TP).
  const onlyFp = evaluateParityGate({
    diffText: diff,
    commitMessages: 'feat(oracle): loosen check\n\nKernel-change: loosening allow readback diff\nParity-case: cross-tenant-bola-public-fp\n',
    mode: 'strict',
    rootDir: REPO_ROOT,
  })
  assert.equal(onlyFp.ok, false)
  assert.deepEqual(onlyFp.missingLooseningSides, [{ file: 'src/server/oracle-invariants.ts', missing: ['tp'] }])

  // Loosening with BOTH a covering TP and a covering FP case -> PASS!
  const bothSides = evaluateParityGate({
    diffText: diff,
    commitMessages: [
      'feat(oracle): loosen check with TP+FP coverage',
      '',
      'Kernel-change: loosening allow readback diff',
      'Parity-case: cross-tenant-bola-tp',
      'Parity-case: cross-tenant-bola-public-fp',
    ].join('\n'),
    mode: 'strict',
    rootDir: REPO_ROOT,
  })
  assert.equal(bothSides.ok, true, `expected TP+FP loosening PASS: ${bothSides.reason}`)

  // When R3-05 Reviewed-by enforcement is enabled, loosening without Reviewed-by fails and with Reviewed-by passes.
  const noReview = evaluateParityGate({
    diffText: diff,
    commitMessages: [
      'feat(oracle): loosen check',
      '',
      'Kernel-change: loosening allow readback diff',
      'Parity-case: cross-tenant-bola-tp',
      'Parity-case: cross-tenant-bola-public-fp',
    ].join('\n'),
    mode: 'strict',
    rootDir: REPO_ROOT,
    requireReviewedByOnLoosening: true,
  })
  assert.equal(noReview.ok, false)
  assert.ok(noReview.reason?.includes('Reviewed-by:'))

  const withReview = evaluateParityGate({
    diffText: diff,
    commitMessages: [
      'feat(oracle): loosen check',
      '',
      'Kernel-change: loosening allow readback diff',
      'Parity-case: cross-tenant-bola-tp',
      'Parity-case: cross-tenant-bola-public-fp',
      'Reviewed-by: claude-opus-4-6 cross-tenant-bola-public-fp',
    ].join('\n'),
    mode: 'strict',
    rootDir: REPO_ROOT,
    requireReviewedByOnLoosening: true,
  })
  assert.equal(withReview.ok, true)
  assert.deepEqual(withReview.reviewedByTrailers, ['claude-opus-4-6 cross-tenant-bola-public-fp'])

  // Malformed short override is rejected.
  const badOverride = evaluateParityGate({
    diffText: diff,
    commitMessages: 'hotfix\n\nKernel-gate-override: skip\n',
    mode: 'strict',
    rootDir: REPO_ROOT,
  })
  assert.equal(badOverride.ok, false)
  assert.equal(badOverride.overridden, false)

  // Audited operator override passes and formats an explicit OVERRIDE report line.
  const goodOverride = evaluateContractChange({
    diffText: diff,
    commitMessages: 'hotfix(oracle): urgent production bypass fix\n\nKernel-gate-override: INC-2026-99 urgent auth bypass hotfix reviewed post-merge\n',
    mode: 'strict',
    sourceLabel: 'hotfix',
    rootDir: REPO_ROOT,
  })
  assert.equal(goodOverride.ok, true)
  assert.equal(goodOverride.parity?.overridden, true)
  const report = formatContractChangeReport({
    ok: true,
    rootDir: REPO_ROOT,
    committed: goodOverride,
    uncommitted: null,
    durationMs: 1,
  })
  assert.ok(report.includes('OVERRIDE'), `expected OVERRIDE in report: ${report}`)
})

// ============================================================================
// 5. Semantic @kernel / @fixes test tag protection
// ============================================================================

test('R3-04 semantic test tags: 14/14 r4-*.test.ts suites carry @kernel+@fixes and are protected regardless of filename', (t) => {
  const r4Files = readdirSync(join(REPO_ROOT, 'tests'))
    .filter(f => f.startsWith('r4-') && f.endsWith('.test.ts'))
    .sort()
  assert.equal(r4Files.length, 14, `expected 14 r4-*.test.ts suites, found ${r4Files.length}`)

  for (const file of r4Files) {
    const rel = `tests/${file}`
    const tags = readTestFileTags(rel, REPO_ROOT)
    assert.equal(tags.kernel, true, `${rel} must carry // @kernel header tag`)
    assert.ok(tags.fixes.length > 0, `${rel} must carry // @fixes <ID> header tag`)
    assert.equal(hasProtectedTestTag(tags), true)
    assert.equal(isGateOrKernelTestFile(rel, { rootDir: REPO_ROOT }), true, `${rel} must be protected by check-contract-change`)
  }

  // Verify parser handles single-line, multi-line, JSDoc, and ignores tags inside code bodies.
  assert.deepEqual(parseTestFileTags('// @kernel @fixes R4-C-1, R4-C-3\nimport assert from "node:assert"\n'), {
    kernel: true,
    fixes: ['R4-C-1', 'R4-C-3'],
  })
  assert.deepEqual(parseTestFileTags('/**\n * @kernel\n * @fixes R3-04\n */\nexport {}\n'), {
    kernel: true,
    fixes: ['R3-04'],
  })
  assert.deepEqual(parseTestFileTags('const x = 1\n// @kernel\n'), {
    kernel: false,
    fixes: [],
  })

  // Arbitrary filename (no r2-/r3-/oracle/security prefix!) is protected solely by its semantic tag.
  const dir = makeTempDir(t, 'r304-tags-')
  mkdirSync(join(dir, 'tests'), { recursive: true })
  writeFileSync(join(dir, 'tests/custom-invariant.test.ts'), '// @kernel @fixes R5-01\nassert.equal(x, 10)\n')
  writeFileSync(join(dir, 'tests/plain-ui-helper.test.ts'), '// helper\nassert.equal(x, 10)\n')

  assert.equal(isGateOrKernelTestFile('tests/custom-invariant.test.ts', { rootDir: dir }), true)
  assert.equal(isGateOrKernelTestFile('tests/plain-ui-helper.test.ts', { rootDir: dir }), false)

  const taggedDiff = [
    'diff --git a/tests/custom-invariant.test.ts b/tests/custom-invariant.test.ts',
    '--- a/tests/custom-invariant.test.ts',
    '+++ b/tests/custom-invariant.test.ts',
    '@@ -1,2 +1,2 @@',
    ' // @kernel @fixes R5-01',
    '-assert.equal(x, 10)',
    '+assert.equal(x, 99)',
  ].join('\n')
  const hits = detectContractChanges(taggedDiff, { rootDir: dir })
  assert.equal(hits.length, 1)
  assert.equal(hits[0]!.file, 'tests/custom-invariant.test.ts')
  assert.equal(hits[0]!.kind, 'gate_assert_literal_change')

  // Verify CLI stays green on synthetic repo when tagged file assertion edit carries a Contract-change trailer.
  const { repo, git } = makeTempGitRepo(t, 'r304-tag-cli-')
  mkdirSync(join(repo, 'tests'), { recursive: true })
  writeFileSync(join(repo, 'tests/custom-invariant.test.ts'), '// @fixes R5-01\nassert.equal(x, 10)\n')
  git('add', '.')
  git('commit', '-m', 'init')

  writeFileSync(join(repo, 'tests/custom-invariant.test.ts'), '// @fixes R5-01\nassert.equal(x, 25)\n')
  git('add', '.')
  git('commit', '-m', 'quietly loosen tagged test')

  const cliFail = spawnSync(process.execPath, [CHECK_CONTRACT_TS, '--root', repo, '--base', 'HEAD~1'], { encoding: 'utf8' })
  assert.equal(cliFail.status, 1, 'editing numeric assert literal in @fixes-tagged test without trailer must FAIL')

  git('commit', '--amend', '-m', 'update tagged test\n\nContract-change: tests/custom-invariant.test.ts intentional threshold update')
  const cliPass = spawnSync(process.execPath, [CHECK_CONTRACT_TS, '--root', repo, '--base', 'HEAD~1'], { encoding: 'utf8' })
  assert.equal(cliPass.status, 0, `expected PASS with trailer: ${cliPass.stderr}`)
})
