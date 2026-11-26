#!/usr/bin/env node
/**
 * Verdict-Flip & Gate-Repair Tests-Only Guard (`R3-05`, plans/claude_quality_3.md §5).
 *
 * Scans commits against `--base <ref>` for two classes of silent kernel drift:
 *   1. Verdict flips & existing fixture edits inside kernel suites (`@kernel` header tag,
 *      `KERNEL_TEST_RE`, or `tests/parity/corpus/*.json`):
 *      - Any `true <-> false` flip (or silent removal) of a `confirmed`/verdict assertion or
 *        expected-verdict literal, OR
 *      - Any edit to an existing TP/FP fixture (status, body, headers, role, arm, side, etc.)
 *        inside a kernel suite or existing parity corpus JSON file.
 *      Requires a `Verdict-flip: <case> <reason>` commit trailer.
 *   2. Gate-repair commits (`fix(worker-gate)`, `test(worker-gate)`, `fix(gate)`) that touch
 *      files outside `tests/`:
 *      Requires BOTH `Kernel-change: <detail>` AND `Reviewed-by: <reviewer>` trailers.
 *
 * Usage:
 *   node scripts/check-verdict-flip.ts [--base <ref>] [--root <dir>] [--staged] [--check-head]
 *                                      [--commit-msg <text>] [--json] [-h|--help]
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  isParityCorpusFile,
  parseUnifiedDiff,
  resolveCommitBaseRef,
  type ParsedDiffFile,
} from './check-contract-change.ts'
import { KERNEL_TEST_RE } from './test-tiers.ts'

export type VerdictFlipHitKind =
  | 'verdict_assertion_flip'
  | 'kernel_fixture_edit'
  | 'corpus_verdict_flip'
  | 'corpus_fixture_edit'

export interface VerdictFlipHit {
  kind: VerdictFlipHitKind
  file: string
  line: number
  before: string
  after: string
  detail: string
}

export interface VerdictFlipTrailer {
  caseId: string
  reason: string
  raw: string
}

export interface GateRepairViolation {
  subject: string
  nonTestFiles: string[]
  missingTrailers: Array<'Kernel-change' | 'Reviewed-by'>
  reason: string
}

export interface VerdictFlipCommitResult {
  sha: string
  subject: string
  ok: boolean
  hits: VerdictFlipHit[]
  verdictFlipTrailers: VerdictFlipTrailer[]
  gateRepairViolation: GateRepairViolation | null
  violations: string[]
}

export interface VerdictFlipRepoResult {
  ok: boolean
  rootDir: string
  sourceLabel: string
  commits: VerdictFlipCommitResult[]
  totalHits: number
  totalViolations: number
  durationMs: number
}

export interface CheckVerdictFlipRepoOptions {
  rootDir?: string
  baseRef?: string | null
  stagedOnly?: boolean
  checkHead?: boolean
  commitMessageOverride?: string | null
}

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

export const GATE_REPAIR_SUBJECT_RE = /^(?:fix|test)\(\s*(?:worker-)?gate\s*\)/i

const KERNEL_TAG_LINE_RE = /^\s*(?:\/\/|\/\*|\*)\s*@kernel\b/i
const VERDICT_FLIP_TRAILER_ALL_RE = /^\s*Verdict-flip:\s*(\S+)\s+(.+)$/gim
const KERNEL_CHANGE_TRAILER_RE = /^\s*Kernel-change:\s*(\S.{2,})$/im
const REVIEWED_BY_TRAILER_RE = /^\s*Reviewed-by:\s*(\S.{2,})$/im

const CORPUS_CONFIRMED_RE = /"confirmed"\s*:\s*(true|false)\b/
const CORPUS_SIDE_RE = /"side"\s*:\s*"(tp|fp)"/

const FIXTURE_PROPERTY_RE =
  /\b(?:status|statusCode|httpStatus|body|responseBody|bodyText|headers|responseHeaders|method|pathAndQuery|role|arm|side|persona|tenant|claimedImpact|claimedBoundary|vulnClass|cwe)\s*:/

function normalizePath(relPath: string): string {
  return relPath.replace(/\\/g, '/').replace(/^\.\//, '')
}

function stripLineComment(line: string): string {
  let quote: string | null = null
  let escaped = false
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]!
    const next = line[i + 1]
    if (quote) {
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === quote) quote = null
      continue
    }
    if (ch === '/' && next === '/') return line.slice(0, i)
    if (ch === "'" || ch === '"' || ch === '`') quote = ch
  }
  return line
}

function normalizeJsonOrCodeLine(line: string): string {
  return line.trim().replace(/,\s*$/, '')
}

function hasKernelTagInText(text: string): boolean {
  const lines = text.split(/\r?\n/).slice(0, 40)
  for (const line of lines) {
    if (KERNEL_TAG_LINE_RE.test(line)) return true
  }
  return false
}

export function isKernelTaggedTestFile(
  relPath: string,
  rootDir?: string,
  taggedKernelFiles?: ReadonlySet<string>,
): boolean {
  const norm = normalizePath(relPath)
  if (isParityCorpusFile(norm)) return true
  if (KERNEL_TEST_RE.test(norm)) return true
  if (taggedKernelFiles?.has(norm)) return true
  if (rootDir && norm.startsWith('tests/') && norm.endsWith('.test.ts')) {
    const abs = join(rootDir, norm)
    if (existsSync(abs)) {
      try {
        const head = readFileSync(abs, 'utf8').slice(0, 4096)
        if (hasKernelTagInText(head)) return true
      } catch {
        // Ignore unreadable file
      }
    }
  }
  return false
}

export function isGateRepairSubject(subject: string): boolean {
  return GATE_REPAIR_SUBJECT_RE.test(subject.trim())
}

export function parseVerdictFlipTrailers(commitMessage: string): VerdictFlipTrailer[] {
  const trailers: VerdictFlipTrailer[] = []
  VERDICT_FLIP_TRAILER_ALL_RE.lastIndex = 0
  for (const m of commitMessage.matchAll(VERDICT_FLIP_TRAILER_ALL_RE)) {
    const caseId = (m[1] ?? '').trim()
    const reason = (m[2] ?? '').trim()
    if (caseId.length >= 2 && reason.length >= 6) {
      trailers.push({ caseId, reason, raw: `${caseId} ${reason}` })
    }
  }
  return trailers
}

export function extractVerdictPolarity(rawLine: string): 'true' | 'false' | null {
  const line = stripLineComment(rawLine).trim()
  if (!line) return null

  // assert.equal / assert.strictEqual on confirmed/verdict/shouldConfirm/expectConfirmed
  const assertBool =
    /\bassert\.(?:strictEqual|equal)\s*\([^,]*\b(?:confirmed|verdict|shouldConfirm|expectConfirmed|expectedConfirmed)\b[^,]*,\s*(true|false)\b/i.exec(
      line,
    )
  if (assertBool) return assertBool[1]!.toLowerCase() as 'true' | 'false'

  // assert.equal / assert.strictEqual on verdict string literal ('confirmed' vs 'rejected'/'unconfirmed'/...)
  const assertVerdictStr =
    /\bassert\.(?:strictEqual|equal)\s*\([^,]*\bverdict\b[^,]*,\s*['"](confirmed|rejected|unconfirmed|denied|false_positive|not_confirmed)['"]/i.exec(
      line,
    )
  if (assertVerdictStr) {
    return assertVerdictStr[1]!.toLowerCase() === 'confirmed' ? 'true' : 'false'
  }

  // assert.ok(res.confirmed) vs assert.ok(!res.confirmed)
  const assertOk = /\bassert\.ok\s*\(\s*(!)?\s*[^,)]*\b(?:confirmed|shouldConfirm)\b/i.exec(line)
  if (assertOk) {
    return assertOk[1] ? 'false' : 'true'
  }

  // Equality check inside assertion or expression: .confirmed === true / false
  const cmpBool =
    /\b(?:confirmed|verdict|shouldConfirm|expectConfirmed|expectedConfirmed)\s*===?\s*(true|false)\b/i.exec(line)
  if (cmpBool) return cmpBool[1]!.toLowerCase() as 'true' | 'false'

  const cmpVerdictStr =
    /\bverdict\s*===?\s*['"](confirmed|rejected|unconfirmed|denied|false_positive|not_confirmed)['"]/i.exec(line)
  if (cmpVerdictStr) {
    return cmpVerdictStr[1]!.toLowerCase() === 'confirmed' ? 'true' : 'false'
  }

  // Object literal property: confirmed: true/false, expectedConfirmed: true/false, verdict: 'confirmed'/'rejected'
  const propBool =
    /(?:['"]?(?:confirmed|shouldConfirm|expectConfirmed|expectedConfirmed)['"]?)\s*:\s*(true|false)\b/.exec(line)
  if (propBool) return propBool[1]!.toLowerCase() as 'true' | 'false'

  const propVerdictStr =
    /(?:['"]?(?:verdict|expectedVerdict)['"]?)\s*:\s*['"](confirmed|rejected|unconfirmed|denied|false_positive|not_confirmed)['"]/i.exec(
      line,
    )
  if (propVerdictStr) {
    return propVerdictStr[1]!.toLowerCase() === 'confirmed' ? 'true' : 'false'
  }

  return null
}

interface DiffFileMeta {
  file: string
  isNewFile: boolean
  isDeleted: boolean
  hasKernelTagInDiff: boolean
}

function extractDiffFileMetadata(diffText: string): Map<string, DiffFileMeta> {
  const map = new Map<string, DiffFileMeta>()
  let current: DiffFileMeta | null = null

  for (const rawLine of diffText.split(/\r?\n/)) {
    if (rawLine.startsWith('diff --git ')) {
      const m = /^diff --git [abciwo]\/(.+?) [abciwo]\/(.+)$/.exec(rawLine)
      const file = normalizePath(m ? m[2]! : '')
      current = { file, isNewFile: false, isDeleted: false, hasKernelTagInDiff: false }
      if (file) map.set(file, current)
      continue
    }
    if (!current) continue
    if (rawLine.startsWith('new file mode ') || rawLine.startsWith('--- /dev/null')) {
      current.isNewFile = true
    } else if (rawLine.startsWith('deleted file mode ') || rawLine.startsWith('+++ /dev/null')) {
      current.isDeleted = true
    } else if (/^\+\+\+ [abciwo]\//.test(rawLine)) {
      const file = normalizePath(rawLine.slice(6).trim())
      if (file && file !== current.file) {
        map.delete(current.file)
        current.file = file
        map.set(file, current)
      }
    } else if (
      (rawLine.startsWith('+') || rawLine.startsWith('-') || rawLine.startsWith(' ')) &&
      !rawLine.startsWith('+++') &&
      !rawLine.startsWith('---')
    ) {
      if (KERNEL_TAG_LINE_RE.test(rawLine.slice(1))) {
        current.hasKernelTagInDiff = true
      }
    }
  }
  return map
}

function detectCorpusFileHits(fileEntry: ParsedDiffFile, meta: DiffFileMeta | undefined): VerdictFlipHit[] {
  const hits: VerdictFlipHit[] = []
  // Adding a brand-new corpus case (e.g., reviewer bypass FP case) is never a verdict flip.
  if (meta?.isNewFile) return hits

  if (meta?.isDeleted || fileEntry.deleted) {
    hits.push({
      kind: 'corpus_fixture_edit',
      file: fileEntry.file,
      line: 1,
      before: fileEntry.file,
      after: '(deleted)',
      detail: `Existing parity corpus case deleted (${fileEntry.file})`,
    })
    return hits
  }

  for (const hunk of fileEntry.hunks) {
    if (hunk.removed.length === 0) continue

    const addedNormSet = new Set(hunk.added.map(a => normalizeJsonOrCodeLine(a.text)))
    const meaningfulRemoved = hunk.removed.filter(r => {
      const norm = normalizeJsonOrCodeLine(r.text)
      if (!norm) return false
      // Ignore trailing-comma-only edits caused by appending additive keys like `covers` or `provenance`.
      return !addedNormSet.has(norm)
    })

    if (meaningfulRemoved.length === 0) continue

    const remConfirmed = meaningfulRemoved
      .map(r => ({ lineNo: r.lineNo, text: r.text.trim(), val: CORPUS_CONFIRMED_RE.exec(r.text)?.[1] }))
      .find(x => x.val !== undefined)
    const addConfirmed = hunk.added
      .map(a => ({ lineNo: a.lineNo, text: a.text.trim(), val: CORPUS_CONFIRMED_RE.exec(a.text)?.[1] }))
      .find(x => x.val !== undefined)

    const remSide = meaningfulRemoved
      .map(r => ({ lineNo: r.lineNo, text: r.text.trim(), val: CORPUS_SIDE_RE.exec(r.text)?.[1] }))
      .find(x => x.val !== undefined)
    const addSide = hunk.added
      .map(a => ({ lineNo: a.lineNo, text: a.text.trim(), val: CORPUS_SIDE_RE.exec(a.text)?.[1] }))
      .find(x => x.val !== undefined)

    if (remConfirmed && (!addConfirmed || addConfirmed.val !== remConfirmed.val)) {
      hits.push({
        kind: 'corpus_verdict_flip',
        file: fileEntry.file,
        line: addConfirmed?.lineNo ?? remConfirmed.lineNo,
        before: remConfirmed.text,
        after: addConfirmed ? addConfirmed.text : '(removed)',
        detail: `Parity corpus expected.confirmed flipped (${remConfirmed.val} -> ${addConfirmed?.val ?? 'removed'})`,
      })
      continue
    }

    if (remSide && (!addSide || addSide.val !== remSide.val)) {
      hits.push({
        kind: 'corpus_verdict_flip',
        file: fileEntry.file,
        line: addSide?.lineNo ?? remSide.lineNo,
        before: remSide.text,
        after: addSide ? addSide.text : '(removed)',
        detail: `Parity corpus side flipped (${remSide.val} -> ${addSide?.val ?? 'removed'})`,
      })
      continue
    }

    const firstRem = meaningfulRemoved[0]!
    const firstAdd = hunk.added.find(a => {
      const n = normalizeJsonOrCodeLine(a.text)
      return n.length > 0 && !hunk.removed.some(r => normalizeJsonOrCodeLine(r.text) === n)
    })
    hits.push({
      kind: 'corpus_fixture_edit',
      file: fileEntry.file,
      line: firstAdd?.lineNo ?? firstRem.lineNo,
      before: firstRem.text.trim(),
      after: firstAdd ? firstAdd.text.trim() : '(removed)',
      detail: `Existing parity corpus fixture modified in ${fileEntry.file}`,
    })
  }

  return hits
}

function detectKernelTestHits(fileEntry: ParsedDiffFile, meta: DiffFileMeta | undefined): VerdictFlipHit[] {
  const hits: VerdictFlipHit[] = []
  if (meta?.isNewFile) return hits

  for (const hunk of fileEntry.hunks) {
    if (hunk.removed.length === 0) continue

    // 1. Check verdict polarity changes (`true <-> false` flips or deleted verdict assertions).
    const remVerdicts = hunk.removed
      .map(r => ({ ...r, polarity: extractVerdictPolarity(r.text) }))
      .filter((r): r is { lineNo: number; text: string; polarity: 'true' | 'false' } => r.polarity !== null)

    const addVerdicts = hunk.added
      .map(a => ({ ...a, polarity: extractVerdictPolarity(a.text) }))
      .filter((a): a is { lineNo: number; text: string; polarity: 'true' | 'false' } => a.polarity !== null)

    if (remVerdicts.length > 0) {
      const remCounts = { true: 0, false: 0 }
      const addCounts = { true: 0, false: 0 }
      for (const r of remVerdicts) remCounts[r.polarity] += 1
      for (const a of addVerdicts) addCounts[a.polarity] += 1

      if (remCounts.true > addCounts.true || remCounts.false > addCounts.false) {
        const flippedRem =
          remVerdicts.find(r => remCounts[r.polarity] > addCounts[r.polarity]) ?? remVerdicts[0]!
        const oppositeAdd =
          addVerdicts.find(a => a.polarity !== flippedRem.polarity) ?? addVerdicts[0]
        hits.push({
          kind: 'verdict_assertion_flip',
          file: fileEntry.file,
          line: oppositeAdd?.lineNo ?? flippedRem.lineNo,
          before: flippedRem.text.trim(),
          after: oppositeAdd ? oppositeAdd.text.trim() : '(verdict assertion removed)',
          detail: oppositeAdd
            ? `Verdict polarity flipped (${flippedRem.polarity} -> ${oppositeAdd.polarity})`
            : `Verdict assertion removed (was ${flippedRem.polarity})`,
        })
        continue
      }
    }

    // 2. Check edits to existing TP/FP fixture fields (e.g., probe status 404 -> 200, body/role/arm edits).
    const addedNormSet = new Set(hunk.added.map(a => normalizeJsonOrCodeLine(stripLineComment(a.text))))
    const editedFixtureRem = hunk.removed.find(r => {
      const stripped = stripLineComment(r.text)
      if (!FIXTURE_PROPERTY_RE.test(stripped)) return false
      const norm = normalizeJsonOrCodeLine(stripped)
      return norm.length > 0 && !addedNormSet.has(norm)
    })

    if (editedFixtureRem) {
      const matchingAdd = hunk.added.find(a => {
        const stripped = stripLineComment(a.text)
        return FIXTURE_PROPERTY_RE.test(stripped) && !hunk.removed.some(
          r => normalizeJsonOrCodeLine(stripLineComment(r.text)) === normalizeJsonOrCodeLine(stripped),
        )
      })
      hits.push({
        kind: 'kernel_fixture_edit',
        file: fileEntry.file,
        line: matchingAdd?.lineNo ?? editedFixtureRem.lineNo,
        before: editedFixtureRem.text.trim(),
        after: matchingAdd ? matchingAdd.text.trim() : '(fixture field removed)',
        detail: `Existing kernel suite TP/FP fixture modified in ${fileEntry.file}`,
      })
    }
  }

  return hits
}

export function detectVerdictFlips(
  diffText: string,
  opts: { rootDir?: string; taggedKernelFiles?: ReadonlySet<string> } = {},
): VerdictFlipHit[] {
  const parsedFiles = parseUnifiedDiff(diffText)
  const metaByFile = extractDiffFileMetadata(diffText)
  const hits: VerdictFlipHit[] = []

  for (const fileEntry of parsedFiles) {
    const norm = normalizePath(fileEntry.file)
    const meta = metaByFile.get(norm)
    if (isParityCorpusFile(norm)) {
      hits.push(...detectCorpusFileHits({ ...fileEntry, file: norm }, meta))
      continue
    }
    const isKernelSuite =
      isKernelTaggedTestFile(norm, opts.rootDir, opts.taggedKernelFiles) ||
      (norm.startsWith('tests/') && norm.endsWith('.test.ts') && Boolean(meta?.hasKernelTagInDiff))
    if (!isKernelSuite) continue
    hits.push(...detectKernelTestHits({ ...fileEntry, file: norm }, meta))
  }

  return hits
}

export function evaluateVerdictFlipCommit(opts: {
  sha?: string
  subject: string
  commitMessage: string
  diffText: string
  changedFiles?: readonly string[]
  rootDir?: string
  taggedKernelFiles?: ReadonlySet<string>
}): VerdictFlipCommitResult {
  const sha = opts.sha ?? 'HEAD'
  const subject = opts.subject.trim()
  const hits = detectVerdictFlips(opts.diffText, {
    rootDir: opts.rootDir,
    taggedKernelFiles: opts.taggedKernelFiles,
  })
  const verdictFlipTrailers = parseVerdictFlipTrailers(opts.commitMessage)
  const violations: string[] = []

  if (hits.length > 0 && verdictFlipTrailers.length === 0) {
    violations.push(
      `Commit ${sha.slice(0, 8)} ("${subject}") contains ${hits.length} kernel verdict-flip/fixture edit(s) without a "Verdict-flip: <case> <reason>" trailer.`,
    )
  }

  let gateRepairViolation: GateRepairViolation | null = null
  if (isGateRepairSubject(subject)) {
    const touchedFiles = opts.changedFiles
      ? [...new Set(opts.changedFiles.map(normalizePath).filter(Boolean))]
      : [...new Set(parseUnifiedDiff(opts.diffText).map(f => normalizePath(f.file)).filter(Boolean))]
    const nonTestFiles = touchedFiles.filter(f => !f.startsWith('tests/'))
    if (nonTestFiles.length > 0) {
      const missingTrailers: Array<'Kernel-change' | 'Reviewed-by'> = []
      if (!KERNEL_CHANGE_TRAILER_RE.test(opts.commitMessage)) missingTrailers.push('Kernel-change')
      if (!REVIEWED_BY_TRAILER_RE.test(opts.commitMessage)) missingTrailers.push('Reviewed-by')
      if (missingTrailers.length > 0) {
        const reason = `Gate-repair commit ${sha.slice(0, 8)} ("${subject}") edits non-test file(s) (${nonTestFiles.join(', ')}) and requires BOTH "Kernel-change:" and "Reviewed-by:" trailers (missing: ${missingTrailers.join(', ')}).`
        gateRepairViolation = { subject, nonTestFiles, missingTrailers, reason }
        violations.push(reason)
      }
    }
  }

  return {
    sha,
    subject,
    ok: violations.length === 0,
    hits,
    verdictFlipTrailers,
    gateRepairViolation,
    violations,
  }
}

function runGit(rootDir: string, args: string[]): { ok: boolean; stdout: string } {
  try {
    const stdout = execFileSync('git', args, {
      cwd: rootDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 16 * 1024 * 1024,
    })
    return { ok: true, stdout }
  } catch {
    return { ok: false, stdout: '' }
  }
}

export function checkVerdictFlipRepo(opts: CheckVerdictFlipRepoOptions = {}): VerdictFlipRepoResult {
  const startedAt = performance.now()
  const rootDir = resolve(opts.rootDir ?? REPO_ROOT)

  if (opts.stagedOnly) {
    const diffRes = runGit(rootDir, [
      '-c', 'diff.mnemonicPrefix=false',
      '-c', 'diff.noprefix=false',
      'diff', '--no-ext-diff', '--cached', '--unified=3',
    ])
    const msg = opts.commitMessageOverride ?? ''
    const subject = msg.split(/\r?\n/).find(l => l.trim().length > 0)?.trim() ?? '(staged)'
    const commitRes = evaluateVerdictFlipCommit({
      sha: 'STAGED',
      subject,
      commitMessage: msg,
      diffText: diffRes.stdout,
      rootDir,
    })
    return {
      ok: commitRes.ok,
      rootDir,
      sourceLabel: 'staged (--cached)',
      commits: [commitRes],
      totalHits: commitRes.hits.length,
      totalViolations: commitRes.violations.length,
      durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
    }
  }

  const baseRef = resolveCommitBaseRef(rootDir, opts.baseRef, opts.checkHead)
  if (!baseRef) {
    return {
      ok: true,
      rootDir,
      sourceLabel: 'committed (0 commits ahead of base)',
      commits: [],
      totalHits: 0,
      totalViolations: 0,
      durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
    }
  }

  const range = `${baseRef}..HEAD`
  const revList = runGit(rootDir, ['rev-list', '--reverse', '--no-merges', range])
  const shas = revList.ok
    ? revList.stdout.split(/\r?\n/).map(s => s.trim()).filter(Boolean)
    : []

  // Fallback for ranges containing only merge commits (e.g. a squash/merge commit).
  const targetShas =
    shas.length > 0
      ? shas
      : runGit(rootDir, ['rev-list', '--reverse', range]).stdout
          .split(/\r?\n/)
          .map(s => s.trim())
          .filter(Boolean)

  const commits: VerdictFlipCommitResult[] = []
  for (const sha of targetShas) {
    const msgRes =
      opts.commitMessageOverride != null && targetShas.length === 1
        ? { ok: true, stdout: opts.commitMessageOverride }
        : runGit(rootDir, ['show', '-s', '--format=%B', sha])
    const commitMessage = msgRes.stdout
    const subject = commitMessage.split(/\r?\n/).find(l => l.trim().length > 0)?.trim() ?? ''
    const diffRes = runGit(rootDir, [
      '-c', 'diff.mnemonicPrefix=false',
      '-c', 'diff.noprefix=false',
      'show', '--no-ext-diff', '--first-parent', '-m', '--format=', '--unified=3', sha,
    ])
    const filesRes = runGit(rootDir, ['diff-tree', '--no-commit-id', '--name-only', '-r', '--first-parent', '-m', sha])
    const changedFiles = filesRes.ok
      ? filesRes.stdout.split(/\r?\n/).map(s => s.trim()).filter(Boolean)
      : undefined

    commits.push(
      evaluateVerdictFlipCommit({
        sha,
        subject,
        commitMessage,
        diffText: diffRes.stdout,
        changedFiles,
        rootDir,
      }),
    )
  }

  const totalHits = commits.reduce((acc, c) => acc + c.hits.length, 0)
  const totalViolations = commits.reduce((acc, c) => acc + c.violations.length, 0)
  return {
    ok: totalViolations === 0,
    rootDir,
    sourceLabel: `committed (${range})`,
    commits,
    totalHits,
    totalViolations,
    durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
  }
}

export function formatVerdictFlipReport(result: VerdictFlipRepoResult): string {
  if (result.ok) {
    const authorizedCommits = result.commits.filter(c => c.hits.length > 0).length
    const suffix =
      result.totalHits > 0
        ? `${result.totalHits} flip/fixture edit(s) across ${authorizedCommits} commit(s) authorized by Verdict-flip trailer`
        : '0 un-trailered verdict flips or gate-repair violations'
    return `check-verdict-flip [${result.sourceLabel}]: PASS (${result.commits.length} commit(s) scanned, ${suffix} in ${result.durationMs}ms)`
  }

  const lines: string[] = [
    `check-verdict-flip [${result.sourceLabel}]: FAIL (${result.totalViolations} violation(s) across ${result.commits.length} commit(s)):`,
  ]
  for (const commit of result.commits) {
    if (commit.ok) continue
    for (const v of commit.violations) {
      lines.push(`  - ${v}`)
    }
    for (const h of commit.hits) {
      lines.push(`    ${h.file}:${h.line} [${h.kind}] ${h.detail}: ${h.before} -> ${h.after}`)
    }
  }
  return lines.join('\n')
}

const usage = `Kovo Hunter Verdict-Flip & Gate-Repair Tests-Only Guard (R3-05)

Usage:
  node scripts/check-verdict-flip.ts [options]

Options:
  --base <ref>             Check commits in merge-base(<ref>, HEAD)..HEAD (default: auto merge-base)
  --check-head             Check HEAD~1..HEAD when at base ref
  --staged                 Check staged diff (--cached)
  --commit-msg <text>      Override commit message text (for hooks / tests)
  --commit-msg-file <path> Read commit message text from file
  --root <dir>             Repository root directory (default: repo root)
  --json                   Emit structured JSON result
  -h, --help               Show this help
`

export function main(argv: string[] = process.argv.slice(2)): number {
  let rootDir = REPO_ROOT
  let baseRef: string | null = null
  let stagedOnly = false
  let checkHead = false
  let commitMessageOverride: string | null = null
  let json = false

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--help' || arg === '-h') {
      process.stdout.write(usage)
      return 0
    }
    if (arg === '--json') { json = true; continue }
    if (arg === '--staged') { stagedOnly = true; continue }
    if (arg === '--check-head') { checkHead = true; continue }
    if (arg === '--base') {
      const next = argv[i + 1]
      if (next === undefined) { process.stderr.write('error: --base requires a git ref\n'); return 2 }
      baseRef = next; i += 1; continue
    }
    if (arg === '--root') {
      const next = argv[i + 1]
      if (!next) { process.stderr.write('error: --root requires a directory\n'); return 2 }
      rootDir = resolve(next); i += 1; continue
    }
    if (arg === '--commit-msg') {
      const next = argv[i + 1]
      if (next === undefined) { process.stderr.write('error: --commit-msg requires text\n'); return 2 }
      commitMessageOverride = next; i += 1; continue
    }
    if (arg === '--commit-msg-file') {
      const next = argv[i + 1]
      if (!next) { process.stderr.write('error: --commit-msg-file requires a file path\n'); return 2 }
      commitMessageOverride = readFileSync(resolve(next), 'utf8'); i += 1; continue
    }
    process.stderr.write(`error: unknown argument '${arg}'\n`)
    return 2
  }

  const result = checkVerdictFlipRepo({
    rootDir,
    baseRef,
    stagedOnly,
    checkHead,
    commitMessageOverride,
  })
  if (json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
  } else {
    const report = `${formatVerdictFlipReport(result)}\n`
    if (result.ok) process.stdout.write(report)
    else process.stderr.write(report)
  }
  return result.ok ? 0 : 1
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(resolve(process.argv[1])).href : false
if (isMain) {
  process.exit(main())
}
