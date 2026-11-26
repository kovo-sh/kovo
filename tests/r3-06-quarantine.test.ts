/**
 * R3-06 regression tests (`plans/claude_quality_3.md` §6):
 *  1. `scripts/test-tiers.ts` backlog owner resolution (`parseStreamBacklog`, `isLiveBacklogOwner`)
 *     and explicit verdict-entry classification (`isExplicitVerdictQuarantineEntry`).
 *  2. `scripts/run-fast-tests.sh` hardened quarantine rules:
 *     - forbids ANY `expires` increase on existing entries vs previous snapshot;
 *     - requires every kernel/critical entry's `ownerStream` to resolve to a live (`ready`/`active`)
 *       row in `plans/STREAM-BACKLOG.md` (rejects invented, completed, or blocked owners);
 *     - rejects quarantining kernel verdict assertions (`assertionKind: 'verdict'`, `[verdict]` /
 *       `verdict:` / `@verdict` names, new `verdict_fp_guard`/`verdict_tp_loss` entries, and
 *       `maxKernelVerdictQuarantinedCases` cap growth), including `@kernel`-tagged suites.
 *  3. Real `tests/QUARANTINE.json` invariants: 0 provider-redaction quarantined entries,
 *     monotone lowered cap matching entry count, staggered kernel expiries (no >50% cliff),
 *     and 0 invalid backlog owners.
 *  4. `scripts/triage-quarantine.ts` deterministic classification, cliff reporting, and rendering.
 *  5. `scripts/check-test-shape.ts` AST detection and monotone downward baseline ratchet.
 */
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  analyzeTestFileShape,
  BASELINE_FILES_WITH_SOURCE_TEXT_REGEX_ASSERTS,
  BASELINE_TOTAL_SOURCE_TEXT_REGEX_ASSERTS,
  scanTestShape,
} from '../scripts/check-test-shape.ts'
import {
  CORE_GATE_INVARIANT_TESTS,
  getLiveBacklogOwners,
  isExplicitVerdictQuarantineEntry,
  isKernelVerdictTriageClass,
  isLiveBacklogOwner,
  isProviderRedactionTestFile,
  parseStreamBacklog,
} from '../scripts/test-tiers.ts'
import {
  buildExpiryCliffSummary,
  classifyTapFailure,
  renderTriageMarkdown,
  triageQuarantine,
} from '../scripts/triage-quarantine.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const RUN_FAST_TESTS_SH = join(REPO_ROOT, 'scripts/run-fast-tests.sh')

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function runFastCheck(args: string[]) {
  const res = spawnSync('bash', [RUN_FAST_TESTS_SH, '--check-only', '--json', ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    timeout: 60_000,
  })
  let parsed: Record<string, unknown> | null = null
  try {
    parsed = JSON.parse(res.stdout)
  } catch {
    parsed = null
  }
  return { status: res.status ?? 1, stdout: res.stdout, stderr: res.stderr, parsed }
}

// ============================================================================
// 1. Stream-backlog owner resolution & verdict helpers (scripts/test-tiers.ts)
// ============================================================================

test('R3-06: parseStreamBacklog and isLiveBacklogOwner accept ready/active rows and reject blocked/completed/invented owners', () => {
  assert.ok(CORE_GATE_INVARIANT_TESTS.includes('tests/r3-06-quarantine.test.ts'))

  const sampleMd = [
    '# Stream backlog',
    '- [ ] `triage-kernel-alpha` — Triage alpha | status: ready | lease: `tests/alpha-oracle.test.ts` | deps: - | stream: `agents/triage-kernel-alpha`',
    '- [ ] `triage-kernel-beta` — Triage beta | status: active | lease: `tests/beta-oracle.test.ts` | deps: - | stream: `swarm/beta-active`',
    '- [ ] `triage-kernel-blocked` — Blocked item | status: blocked | lease: `tests/blocked.test.ts` | deps: `X` | stream: -',
    '- [x] `triage-kernel-done` (`abc1234`) — Done item | stream: `agents/triage-kernel-done`',
  ].join('\n')

  const rows = parseStreamBacklog(sampleMd)
  assert.equal(rows.length, 4)
  const live = getLiveBacklogOwners(rows)
  assert.equal(live.has('triage-kernel-alpha'), true)
  assert.equal(live.has('triage-kernel-beta'), true)
  assert.equal(live.has('beta-active'), true)
  assert.equal(live.has('triage-kernel-blocked'), false)
  assert.equal(live.has('triage-kernel-done'), false)

  assert.equal(isLiveBacklogOwner('triage-kernel-alpha', rows), true)
  assert.equal(isLiveBacklogOwner('triage-kernel-beta', rows), true)
  assert.equal(isLiveBacklogOwner('triage-kernel-blocked', rows), false)
  assert.equal(isLiveBacklogOwner('triage-kernel-done', rows), false)
  assert.equal(isLiveBacklogOwner('triage-kernel-invented', rows), false)
  assert.equal(isLiveBacklogOwner('v7-triage', rows), false)

  assert.equal(isExplicitVerdictQuarantineEntry({ testName: 'C-7 [verdict]: rejects echo', assertionKind: 'prose' }), true)
  assert.equal(isExplicitVerdictQuarantineEntry({ testName: 'verdict: confirms BOLA' }), true)
  assert.equal(isExplicitVerdictQuarantineEntry({ testName: 'ordinary name', assertionKind: 'verdict' }), true)
  assert.equal(isExplicitVerdictQuarantineEntry({ testName: 'ordinary prose name', assertionKind: 'prose' }), false)

  assert.equal(isKernelVerdictTriageClass('verdict_fp_guard'), true)
  assert.equal(isKernelVerdictTriageClass('verdict_tp_loss'), true)
  assert.equal(isKernelVerdictTriageClass('reason_only'), false)
  assert.equal(isKernelVerdictTriageClass('environment_or_harness'), false)
})

// ============================================================================
// 2. Hardened run-fast-tests.sh quarantine enforcement
// ============================================================================

test('R3-06: run-fast-tests.sh forbids expires extensions while allowing staggered earlier expiries', (t) => {
  const dir = makeTempDir(t, 'r306-expiry-')
  const testsDir = join(dir, 'tests')
  mkdirSync(testsDir, { recursive: true })
  writeFileSync(join(testsDir, 'sample-oracle.test.ts'), 'export {}\n')

  const backlogPath = join(dir, 'STREAM-BACKLOG.md')
  writeFileSync(
    backlogPath,
    '- [ ] `triage-kernel-sample` — Triage sample | status: ready | lease: `tests/sample-oracle.test.ts` | deps: - | stream: `agents/triage-kernel-sample`\n',
  )

  const prevQ = join(dir, 'QUARANTINE.prev.json')
  writeFileSync(prevQ, JSON.stringify({
    version: 2,
    maxQuarantinedCases: 1,
    maxKernelVerdictQuarantinedCases: 0,
    entries: [
      {
        file: 'tests/sample-oracle.test.ts',
        testName: 'prose assertion only',
        ownerStream: 'triage-kernel-sample',
        triageClass: 'reason_only',
        reason: 'reason prose mismatch',
        expires: '2026-12-06',
      },
    ],
  }))

  // Extended expiry (2026-12-06 -> 2026-12-09) MUST fail!
  const extendedQ = join(dir, 'QUARANTINE.extended.json')
  writeFileSync(extendedQ, JSON.stringify({
    version: 2,
    maxQuarantinedCases: 1,
    maxKernelVerdictQuarantinedCases: 0,
    entries: [
      {
        file: 'tests/sample-oracle.test.ts',
        testName: 'prose assertion only',
        ownerStream: 'triage-kernel-sample',
        triageClass: 'reason_only',
        reason: 'reason prose mismatch',
        expires: '2026-12-09',
      },
    ],
  }))
  const extRes = runFastCheck([
    '--tests-dir', testsDir,
    '--quarantine', extendedQ,
    '--prev-quarantine', prevQ,
    '--backlog', backlogPath,
    '--now', '2026-11-26',
  ])
  assert.notEqual(extRes.status, 0, 'extending an existing quarantine expiry must fail')
  const extErrors = (extRes.parsed?.errors as string[]) ?? []
  assert.ok(
    extErrors.some(e => e.includes('quarantine expiry extended') && e.includes('2026-12-06 -> 2026-12-09')),
    `expected expiry-extension error, got: ${extErrors.join('; ')}`,
  )

  // Staggered earlier expiry (2026-12-06 -> 2026-12-04) MUST pass!
  const earlierQ = join(dir, 'QUARANTINE.earlier.json')
  writeFileSync(earlierQ, JSON.stringify({
    version: 2,
    maxQuarantinedCases: 1,
    maxKernelVerdictQuarantinedCases: 0,
    entries: [
      {
        file: 'tests/sample-oracle.test.ts',
        testName: 'prose assertion only',
        ownerStream: 'triage-kernel-sample',
        triageClass: 'reason_only',
        reason: 'reason prose mismatch',
        expires: '2026-12-04',
      },
    ],
  }))
  const okRes = runFastCheck([
    '--tests-dir', testsDir,
    '--quarantine', earlierQ,
    '--prev-quarantine', prevQ,
    '--backlog', backlogPath,
    '--now', '2026-11-26',
  ])
  assert.equal(okRes.status, 0, `staggering expiry earlier should pass: ${okRes.stdout} ${okRes.stderr}`)
  assert.equal(okRes.parsed?.ok, true)
})

test('R3-06: run-fast-tests.sh rejects invented/completed kernel owners and kernel verdict quarantine entries (including @kernel tagged suites)', (t) => {
  const dir = makeTempDir(t, 'r306-rules-')
  const testsDir = join(dir, 'tests')
  mkdirSync(testsDir, { recursive: true })
  writeFileSync(join(testsDir, 'sample-oracle.test.ts'), 'export {}\n')
  writeFileSync(join(testsDir, 'custom-tagged.test.ts'), '// @kernel\nexport {}\n')

  const backlogPath = join(dir, 'STREAM-BACKLOG.md')
  writeFileSync(backlogPath, [
    '- [ ] `triage-kernel-live` — Live row | status: active | lease: `tests/sample-oracle.test.ts` | deps: - | stream: `agents/triage-kernel-live`',
    '- [x] `triage-kernel-completed` — Done row | stream: `agents/triage-kernel-completed`',
  ].join('\n') + '\n')

  const prevQ = join(dir, 'QUARANTINE.prev.json')
  writeFileSync(prevQ, JSON.stringify({
    version: 2,
    maxQuarantinedCases: 5,
    maxKernelVerdictQuarantinedCases: 0,
    entries: [],
  }))

  const badQ = join(dir, 'QUARANTINE.bad.json')
  writeFileSync(badQ, JSON.stringify({
    version: 2,
    maxQuarantinedCases: 5,
    maxKernelVerdictQuarantinedCases: 1,
    entries: [
      {
        file: 'tests/sample-oracle.test.ts',
        testName: 'prose case with invented owner',
        ownerStream: 'triage-kernel-invented',
        triageClass: 'reason_only',
        reason: 'drift',
        expires: '2026-12-05',
      },
      {
        file: 'tests/custom-tagged.test.ts',
        testName: 'tagged kernel case with completed owner',
        ownerStream: 'triage-kernel-completed',
        triageClass: 'reason_only',
        reason: 'drift',
        expires: '2026-12-05',
      },
      {
        file: 'tests/sample-oracle.test.ts',
        testName: 'C-7 [verdict]: explicit verdict test',
        ownerStream: 'triage-kernel-live',
        triageClass: 'reason_only',
        assertionKind: 'verdict',
        reason: 'attempted verdict mute',
        expires: '2026-12-05',
      },
      {
        file: 'tests/sample-oracle.test.ts',
        testName: 'brand new kernel verdict failure',
        ownerStream: 'triage-kernel-live',
        triageClass: 'verdict_tp_loss',
        reason: 'new verdict failure',
        expires: '2026-12-05',
      },
    ],
  }))

  const res = runFastCheck([
    '--tests-dir', testsDir,
    '--quarantine', badQ,
    '--prev-quarantine', prevQ,
    '--backlog', backlogPath,
    '--now', '2026-11-26',
  ])
  assert.notEqual(res.status, 0, 'violating backlog owner, verdict prohibition, and verdict cap must fail')
  const errs = (res.parsed?.errors as string[]) ?? []
  assert.ok(errs.some(e => e.includes('triage-kernel-invented') && e.includes('does not resolve to a live')), `missing invented owner error: ${errs.join('; ')}`)
  assert.ok(errs.some(e => e.includes('custom-tagged.test.ts') && e.includes('triage-kernel-completed')), `missing @kernel completed owner error: ${errs.join('; ')}`)
  assert.ok(errs.some(e => e.includes('C-7 [verdict]') && e.includes('cannot be quarantined')), `missing explicit verdict error: ${errs.join('; ')}`)
  assert.ok(errs.some(e => e.includes('brand new kernel verdict failure') && e.includes('verdict_tp_loss') && e.includes('cannot be quarantined')), `missing new verdict_tp_loss error: ${errs.join('; ')}`)
  assert.ok(errs.some(e => e.includes('kernel verdict quarantine cap grew')), `missing verdict cap growth error: ${errs.join('; ')}`)
})

// ============================================================================
// 3. Real repo QUARANTINE.json & triage-quarantine.ts verification
// ============================================================================

test('R3-06: checked-in tests/QUARANTINE.json retires provider-redaction debt, staggers expiries, and passes triage + fast-check', () => {
  const qRaw = JSON.parse(readFileSync(join(REPO_ROOT, 'tests/QUARANTINE.json'), 'utf8')) as {
    version: number
    maxQuarantinedCases: number
    maxKernelVerdictQuarantinedCases: number
    entries: Array<{ file: string; ownerStream: string; expires: string; triageClass?: string }>
  }
  assert.equal(qRaw.version, 2)
  assert.equal(qRaw.entries.length, qRaw.maxQuarantinedCases, 'maxQuarantinedCases must match retired count monotonically')
  assert.ok(qRaw.maxQuarantinedCases <= 180, `expected retired cap <= 180, got ${qRaw.maxQuarantinedCases}`)

  // Zero provider-redaction entries remain quarantined!
  const providerEntries = qRaw.entries.filter(e => isProviderRedactionTestFile(e.file))
  assert.deepEqual(providerEntries, [], 'provider-redaction suites must be completely out of quarantine')

  // Full fast-test validation passes cleanly.
  const checkRes = runFastCheck(['--quarantine', 'tests/QUARANTINE.json'])
  assert.equal(checkRes.status, 0, `checked-in QUARANTINE.json failed fast-check: ${checkRes.stdout} ${checkRes.stderr}`)
  assert.equal(checkRes.parsed?.ok, true)

  // Deterministic triage report passes with 0 invalid owners, 0 expired, and unstaggered cliff eliminated.
  const report1 = triageQuarantine({ rootDir: REPO_ROOT, nowDate: '2026-11-26' })
  const report2 = triageQuarantine({ rootDir: REPO_ROOT, nowDate: '2026-11-26' })
  assert.deepEqual(report1, report2, 'triageQuarantine must be deterministic')
  assert.equal(report1.ok, true, `triage report had issues: ${report1.issues.join('; ')}`)
  assert.equal(report1.invalidOwnerCount, 0)
  assert.equal(report1.explicitVerdictCount, 0)
  assert.equal(report1.expiryCliffAll.expiredCount, 0)
  assert.equal(report1.expiryCliffKernel.concentrated, false, 'kernel expiries must be staggered (peak share <= 50%)')
  assert.ok(
    (report1.expiryCliffKernel.latestExpiry ?? '') <= '2026-12-10',
    `no kernel expiry may exceed 2026-12-10, got ${report1.expiryCliffKernel.latestExpiry}`,
  )

  const md = renderTriageMarkdown(report1)
  assert.ok(md.includes('# Quarantine Triage Report (2026-11-26)'))
  assert.ok(md.includes('| `reason_only` |'))
  assert.ok(md.includes('| `verdict_tp_loss` |'))
})

test('R3-06: classifyTapFailure and buildExpiryCliffSummary classify TP/FP/prose/harness and cliff concentration accurately', () => {
  assert.equal(
    classifyTapFailure('C-7: arbitrary two-value differences do not confirm', {
      name: 'c7',
      status: 'fail',
      operator: 'match',
      actual: "'different message'",
      expected: '',
      errorLine: 'The input did not match the regular expression /opposite/',
    }),
    'reason_only',
  )
  assert.equal(
    classifyTapFailure('FP guard: benign payload must not confirm', {
      name: 'fp',
      status: 'fail',
      operator: 'strictEqual',
      actual: 'true',
      expected: 'false',
      errorLine: 'Expected values to be strictly equal',
    }),
    'verdict_fp_guard',
  )
  assert.equal(
    classifyTapFailure('TP case: genuine BOLA confirms', {
      name: 'tp',
      status: 'fail',
      operator: 'strictEqual',
      actual: 'false',
      expected: 'true',
      errorLine: 'Expected values to be strictly equal',
    }),
    'verdict_tp_loss',
  )
  assert.equal(
    classifyTapFailure('C1.1: agent-session.ts is decomposed below 4,000 LOC', {
      name: 'loc',
      status: 'fail',
      operator: '==',
      actual: 'false',
      expected: 'true',
      errorLine: 'agent-session.ts is 4734 LOC (must be <= 4,200)',
    }),
    'environment_or_harness',
  )

  const cliff = buildExpiryCliffSummary([
    { expires: '2026-12-10', expired: false },
    { expires: '2026-12-10', expired: false },
    { expires: '2026-12-10', expired: false },
    { expires: '2026-12-10', expired: false },
  ])
  assert.equal(cliff.concentrated, true)
  assert.equal(cliff.peakShare, 1)

  const staggered = buildExpiryCliffSummary([
    { expires: '2026-12-03', expired: false },
    { expires: '2026-12-05', expired: false },
    { expires: '2026-12-07', expired: false },
    { expires: '2026-12-09', expired: false },
  ])
  assert.equal(staggered.concentrated, false)
  assert.equal(staggered.peakShare, 0.25)
})

// ============================================================================
// 4. AST-based test-shape ratchet (scripts/check-test-shape.ts)
// ============================================================================

test('R3-06: check-test-shape.ts flags readFileSync(src/**) + assert.match and enforces downward baseline ratchet', (t) => {
  const badSource = [
    "import assert from 'node:assert/strict'",
    "import { readFileSync } from 'node:fs'",
    "const src = readFileSync('src/server/example.ts', 'utf8')",
    'assert.match(src, /internalHelper/)',
    'assert.doesNotMatch(src, /legacyHelper/)',
  ].join('\n')
  const badReport = analyzeTestFileShape(badSource, 'tests/bad-shape.test.ts')
  assert.equal(badReport.srcTextReadLines.length, 1)
  assert.equal(badReport.sourceRegexAssertCount, 2)

  // Behavioral test without src/** readFileSync is NEVER flagged, even if it uses assert.match on runtime output.
  const goodSource = [
    "import assert from 'node:assert/strict'",
    "import { readFileSync } from 'node:fs'",
    "const fixture = readFileSync('tests/fixtures/sample.json', 'utf8')",
    'assert.match(fixture, /expected-output/)',
  ].join('\n')
  const goodReport = analyzeTestFileShape(goodSource, 'tests/good-behavioral.test.ts')
  assert.equal(goodReport.srcTextReadLines.length, 0)
  assert.equal(goodReport.sourceRegexAssertCount, 0)

  // Synthetic workspace ratchet test: unlisted new file and count growth both FAIL; reduction PASSES.
  const dir = makeTempDir(t, 'r306-shape-')
  const testsDir = join(dir, 'tests')
  mkdirSync(testsDir, { recursive: true })
  writeFileSync(join(testsDir, 'existing.test.ts'), badSource)
  writeFileSync(join(testsDir, 'behavioral.test.ts'), goodSource)

  const passScan = scanTestShape({
    rootDir: dir,
    baselineByFile: { 'tests/existing.test.ts': 2 },
  })
  assert.equal(passScan.ok, true)
  assert.equal(passScan.totalSourceRegexAsserts, 2)

  const reducedScan = scanTestShape({
    rootDir: dir,
    baselineByFile: { 'tests/existing.test.ts': 3 },
  })
  assert.equal(reducedScan.ok, true)
  assert.equal(reducedScan.reductions.length, 1)

  const grewScan = scanTestShape({
    rootDir: dir,
    baselineByFile: { 'tests/existing.test.ts': 1 },
  })
  assert.equal(grewScan.ok, false)
  assert.ok(grewScan.regressions.some(r => r.kind === 'count_increased'))

  const newFileScan = scanTestShape({
    rootDir: dir,
    baselineByFile: {},
  })
  assert.equal(newFileScan.ok, false)
  assert.ok(newFileScan.regressions.some(r => r.kind === 'new_file' && r.file === 'tests/existing.test.ts'))

  // Real repo scan passes against its checked-in baseline.
  const repoScan = scanTestShape({ rootDir: REPO_ROOT })
  assert.equal(repoScan.ok, true, `repo test-shape check failed: ${repoScan.regressions.map(r => r.detail).join('; ')}`)
  assert.equal(repoScan.totalSourceRegexAsserts, BASELINE_TOTAL_SOURCE_TEXT_REGEX_ASSERTS)
  assert.equal(repoScan.filesWithSourceRegexAsserts, BASELINE_FILES_WITH_SOURCE_TEXT_REGEX_ASSERTS)
})
