#!/usr/bin/env node
/**
 * Contract-Change Diff Lint (`cq-3-merge-gate`, plans/claude_quality.md #3).
 *
 * Inspects a git diff for edits to:
 *   1. Exported `*_DEFAULT`, `*_BUDGET`, or `*_MS` constants in `src/server/**`
 *      or `scripts/benchmark-core.ts`, OR
 *   2. Numeric literals inside `assert.*` lines of gate or precision-kernel test suites.
 *
 * When any such contract edit is detected in committed changes, the commit range MUST carry
 * a non-empty `Contract-change:` trailer (e.g. `Contract-change: raised budget per ledger-abc123`).
 *
 * Uncommitted working-tree edits warn by default (`--allow-uncommitted`) so local iteration is
 * never blocked before commit; pass `--strict-uncommitted` or `--staged` to enforce strictly.
 */
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

export type ContractChangeKind = 'tunable_constant_change' | 'gate_assert_literal_change'

export interface ContractChangeHit {
  kind: ContractChangeKind
  file: string
  line: number
  symbol?: string
  before: string
  after: string
}

export interface ParsedDiffHunk {
  oldStart: number
  newStart: number
  removed: Array<{ lineNo: number; text: string }>
  added: Array<{ lineNo: number; text: string }>
}

export interface ParsedDiffFile {
  file: string
  hunks: ParsedDiffHunk[]
}

export interface ContractChangeEvalResult {
  ok: boolean
  mode: 'strict' | 'warn'
  sourceLabel: string
  hits: ContractChangeHit[]
  trailerPresent: boolean
  trailerValue: string | null
  warned: boolean
}

export interface ContractChangeRepoResult {
  ok: boolean
  rootDir: string
  committed: ContractChangeEvalResult
  uncommitted: ContractChangeEvalResult | null
  durationMs: number
}

export interface CheckGitRepoOptions {
  rootDir?: string
  baseRef?: string | null
  stagedOnly?: boolean
  checkHead?: boolean
  strictUncommitted?: boolean
  commitMessageOverride?: string | null
}

const GATE_TEST_EXACT = new Set([
  'tests/v4-m7-orch.test.ts',
  'tests/v5-m1-wiring-correctness.test.ts',
  'tests/v5-m2-state.test.ts',
  'tests/sys-contract-canary.test.ts',
  'tests/v7-dispatch-funnel.test.ts',
  'tests/v7-confirm-consistency.test.ts',
  'tests/v8-seam1-golden-e2e.test.ts',
  'tests/cq-3-merge-gate.test.ts',
])

const KERNEL_TEST_RE = /^tests\/.*(?:oracle|receipt|confirm-consistency|floor-recipe|verify-kernel|dispatch-funnel|contract-canary|path-parity|taxonomy-conformance).*\.test\.ts$/

const TUNABLE_EXPORT_RE = /^\s*export\s+(?:const|let)\s+([A-Z][A-Z0-9_]*_(?:DEFAULT|BUDGET|MS))\b[^=]*=\s*(.+)$/
const ASSERT_CALL_RE = /\bassert\.[A-Za-z_]\w*\s*\(/
const NUMERIC_LITERAL_RE = /(?<![A-Za-z0-9_$])(?:\d[\d_]*(?:\.[\d_]+)?|\.\d[\d_]*)(?![A-Za-z0-9_$])/g
const CONTRACT_CHANGE_TRAILER_RE = /^\s*Contract-change:\s*(.+)$/im

export function isGateOrKernelTestFile(relPath: string): boolean {
  const norm = relPath.replace(/\\/g, '/')
  return GATE_TEST_EXACT.has(norm) || KERNEL_TEST_RE.test(norm)
}

export function isTunableSourceFile(relPath: string): boolean {
  const norm = relPath.replace(/\\/g, '/')
  if (norm === 'scripts/benchmark-core.ts') return true
  if (!norm.startsWith('src/server/')) return false
  if (/(?:\.test|\.spec)\.[^./]+$/i.test(norm)) return false
  return norm.endsWith('.ts')
}

/**
 * Strip comments and quoted string literals from a single TS line so numeric literal extraction
 * ignores assertion error messages and comments.
 */
export function stripStringsAndLineComment(line: string): string {
  let out = ''
  let quote: string | null = null
  let escaped = false
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]!
    const next = line[i + 1]
    if (quote) {
      if (escaped) {
        escaped = false
      } else if (ch === '\\') {
        escaped = true
      } else if (ch === quote) {
        quote = null
        out += '""'
      }
      continue
    }
    if (ch === '/' && next === '/') {
      break
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch
      continue
    }
    out += ch
  }
  return out
}

export function extractCodeNumericLiterals(line: string): string[] {
  const stripped = stripStringsAndLineComment(line)
  const matches = stripped.match(NUMERIC_LITERAL_RE)
  if (!matches) return []
  return matches.map(raw => String(Number(raw.replace(/_/g, ''))))
}

function normalizeRhs(rawRhs: string): string {
  const stripped = stripStringsAndLineComment(rawRhs).trim().replace(/;$/, '').trim()
  // Normalize numeric underscores so 6000 -> 6_000 is not flagged as a semantic change.
  return stripped.replace(NUMERIC_LITERAL_RE, m => String(Number(m.replace(/_/g, ''))))
}

export function parseUnifiedDiff(diffText: string): ParsedDiffFile[] {
  const files: ParsedDiffFile[] = []
  let currentFile: ParsedDiffFile | null = null
  let currentHunk: ParsedDiffHunk | null = null
  let oldLine = 0
  let newLine = 0

  for (const rawLine of diffText.split(/\r?\n/)) {
    if (rawLine.startsWith('diff --git ')) {
      currentHunk = null
      const match = /^diff --git [abciwo]\/(.+?) [abciwo]\/(.+)$/.exec(rawLine)
      currentFile = { file: match ? match[2]! : '', hunks: [] }
      files.push(currentFile)
      continue
    }
    if (/^\+\+\+ [abciwo]\//.test(rawLine)) {
      if (currentFile) currentFile.file = rawLine.slice(6).trim()
      continue
    }
    if (rawLine.startsWith('+++ /dev/null')) {
      // File deleted; keep old filename from header so deleted constants can still be observed.
      continue
    }
    if (rawLine.startsWith('@@ ')) {
      const match = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(rawLine)
      if (match && currentFile) {
        oldLine = Number(match[1])
        newLine = Number(match[2])
        currentHunk = { oldStart: oldLine, newStart: newLine, removed: [], added: [] }
        currentFile.hunks.push(currentHunk)
      }
      continue
    }
    if (!currentHunk) continue
    if (rawLine.startsWith('-') && !rawLine.startsWith('---')) {
      currentHunk.removed.push({ lineNo: oldLine, text: rawLine.slice(1) })
      oldLine += 1
    } else if (rawLine.startsWith('+') && !rawLine.startsWith('+++')) {
      currentHunk.added.push({ lineNo: newLine, text: rawLine.slice(1) })
      newLine += 1
    } else if (rawLine.startsWith(' ')) {
      oldLine += 1
      newLine += 1
    }
  }

  return files.filter(f => f.file.length > 0)
}

/** Returns true iff every value in `sub` appears with at least as high multiplicity in `sup`. */
function isSubMultiset(sub: readonly string[], sup: readonly string[]): boolean {
  const counts = new Map<string, number>()
  for (const v of sup) counts.set(v, (counts.get(v) ?? 0) + 1)
  for (const v of sub) {
    const n = counts.get(v) ?? 0
    if (n <= 0) return false
    counts.set(v, n - 1)
  }
  return true
}

export function detectContractChanges(diffText: string): ContractChangeHit[] {
  const parsedFiles = parseUnifiedDiff(diffText)
  const hits: ContractChangeHit[] = []

  for (const fileEntry of parsedFiles) {
    const tunable = isTunableSourceFile(fileEntry.file)
    const gateTest = isGateOrKernelTestFile(fileEntry.file)
    if (!tunable && !gateTest) continue

    for (const hunk of fileEntry.hunks) {
      if (tunable) {
        const removedConsts = new Map<string, { lineNo: number; rhs: string; norm: string }>()
        const addedConsts = new Map<string, { lineNo: number; rhs: string; norm: string }>()
        for (const rem of hunk.removed) {
          const m = TUNABLE_EXPORT_RE.exec(rem.text)
          if (m) removedConsts.set(m[1]!, { lineNo: rem.lineNo, rhs: m[2]!.trim(), norm: normalizeRhs(m[2]!) })
        }
        for (const add of hunk.added) {
          const m = TUNABLE_EXPORT_RE.exec(add.text)
          if (m) addedConsts.set(m[1]!, { lineNo: add.lineNo, rhs: m[2]!.trim(), norm: normalizeRhs(m[2]!) })
        }
        for (const [symbol, before] of removedConsts) {
          const after = addedConsts.get(symbol)
          if (!after) {
            hits.push({
              kind: 'tunable_constant_change',
              file: fileEntry.file,
              line: before.lineNo,
              symbol,
              before: before.rhs,
              after: '(removed)',
            })
          } else if (after.norm !== before.norm) {
            hits.push({
              kind: 'tunable_constant_change',
              file: fileEntry.file,
              line: after.lineNo,
              symbol,
              before: before.rhs,
              after: after.rhs,
            })
          }
        }
      }

      if (gateTest) {
        const remAsserts = hunk.removed
          .filter(r => ASSERT_CALL_RE.test(r.text))
          .map(r => ({ ...r, nums: extractCodeNumericLiterals(r.text) }))
          .filter(r => r.nums.length > 0)
        if (remAsserts.length === 0) continue

        const addAsserts = hunk.added
          .filter(a => ASSERT_CALL_RE.test(a.text))
          .map(a => ({ ...a, nums: extractCodeNumericLiterals(a.text) }))

        const remNums = remAsserts.flatMap(r => r.nums)
        const addNums = addAsserts.flatMap(a => a.nums)
        if (!isSubMultiset(remNums, addNums)) {
          const firstAdd = addAsserts[0]
          const firstRem = remAsserts[0]!
          hits.push({
            kind: 'gate_assert_literal_change',
            file: fileEntry.file,
            line: firstAdd ? firstAdd.lineNo : firstRem.lineNo,
            before: firstRem.text.trim(),
            after: firstAdd ? firstAdd.text.trim() : '(assertion removed)',
          })
        }
      }
    }
  }

  return hits
}

export function hasContractChangeTrailer(commitMessages: string): { present: boolean; trailer: string | null } {
  const m = CONTRACT_CHANGE_TRAILER_RE.exec(commitMessages)
  if (!m) return { present: false, trailer: null }
  const val = m[1]!.trim()
  if (val.length < 6) return { present: false, trailer: null }
  return { present: true, trailer: val }
}

export function evaluateContractChange(opts: {
  diffText: string
  commitMessages: string
  mode: 'strict' | 'warn'
  sourceLabel: string
}): ContractChangeEvalResult {
  const hits = detectContractChanges(opts.diffText)
  if (hits.length === 0) {
    return {
      ok: true,
      mode: opts.mode,
      sourceLabel: opts.sourceLabel,
      hits: [],
      trailerPresent: false,
      trailerValue: null,
      warned: false,
    }
  }
  const trailer = hasContractChangeTrailer(opts.commitMessages)
  if (trailer.present) {
    return {
      ok: true,
      mode: opts.mode,
      sourceLabel: opts.sourceLabel,
      hits,
      trailerPresent: true,
      trailerValue: trailer.trailer,
      warned: false,
    }
  }
  if (opts.mode === 'warn') {
    return {
      ok: true,
      mode: opts.mode,
      sourceLabel: opts.sourceLabel,
      hits,
      trailerPresent: false,
      trailerValue: null,
      warned: true,
    }
  }
  return {
    ok: false,
    mode: opts.mode,
    sourceLabel: opts.sourceLabel,
    hits,
    trailerPresent: false,
    trailerValue: null,
    warned: false,
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

function resolveCommitBaseRef(rootDir: string, explicitBase?: string | null, checkHead?: boolean): string | null {
  if (explicitBase) return explicitBase
  const branch = runGit(rootDir, ['rev-parse', '--abbrev-ref', 'HEAD']).stdout.trim()
  const headSha = runGit(rootDir, ['rev-parse', 'HEAD']).stdout.trim()
  if (!headSha) return null

  // On feature/worktree branches, compare strictly against local main's merge-base.
  // If 0 commits ahead of main, return null (unless --check-head was explicitly requested).
  if (branch && branch !== 'main') {
    const mb = runGit(rootDir, ['merge-base', 'main', 'HEAD'])
    if (mb.ok && mb.stdout.trim()) {
      if (mb.stdout.trim() !== headSha) return mb.stdout.trim()
      if (!checkHead) return null
    }
  }
  // On main (or detached HEAD without main ref), compare against origin/main when unpushed commits exist.
  const originMb = runGit(rootDir, ['merge-base', 'origin/main', 'HEAD'])
  if (originMb.ok && originMb.stdout.trim() && originMb.stdout.trim() !== headSha) {
    return originMb.stdout.trim()
  }
  if (checkHead) {
    const parent = runGit(rootDir, ['rev-parse', 'HEAD~1'])
    if (parent.ok && parent.stdout.trim()) return parent.stdout.trim()
  }
  return null
}

export function checkGitRepo(opts: CheckGitRepoOptions = {}): ContractChangeRepoResult {
  const startedAt = performance.now()
  const rootDir = resolve(opts.rootDir ?? REPO_ROOT)

  if (opts.stagedOnly) {
    const diffRes = runGit(rootDir, ['-c', 'diff.mnemonicPrefix=false', '-c', 'diff.noprefix=false', 'diff', '--no-ext-diff', '--cached', '--unified=3'])
    const commitMessages = opts.commitMessageOverride ?? ''
    const mode = opts.strictUncommitted === false ? 'warn' : 'strict'
    const committed = evaluateContractChange({
      diffText: diffRes.stdout,
      commitMessages,
      mode,
      sourceLabel: 'staged (--cached)',
    })
    return {
      ok: committed.ok,
      rootDir,
      committed,
      uncommitted: null,
      durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
    }
  }

  const baseRef = resolveCommitBaseRef(rootDir, opts.baseRef, opts.checkHead)
  let committed: ContractChangeEvalResult
  if (baseRef) {
    const range = `${baseRef}..HEAD`
    const diffRes = runGit(rootDir, ['-c', 'diff.mnemonicPrefix=false', '-c', 'diff.noprefix=false', 'diff', '--no-ext-diff', '--unified=3', range])
    const logRes = opts.commitMessageOverride != null
      ? { ok: true, stdout: opts.commitMessageOverride }
      : runGit(rootDir, ['log', '--format=%B', range])
    committed = evaluateContractChange({
      diffText: diffRes.stdout,
      commitMessages: logRes.stdout,
      mode: 'strict',
      sourceLabel: `committed (${range})`,
    })
  } else {
    committed = {
      ok: true,
      mode: 'strict',
      sourceLabel: 'committed (0 commits ahead of base)',
      hits: [],
      trailerPresent: false,
      trailerValue: null,
      warned: false,
    }
  }

  const dirtyDiff = runGit(rootDir, ['-c', 'diff.mnemonicPrefix=false', '-c', 'diff.noprefix=false', 'diff', '--no-ext-diff', '--unified=3', 'HEAD'])
  const uncommitted = evaluateContractChange({
    diffText: dirtyDiff.stdout,
    commitMessages: opts.commitMessageOverride ?? '',
    mode: opts.strictUncommitted ? 'strict' : 'warn',
    sourceLabel: 'working tree (uncommitted)',
  })

  return {
    ok: committed.ok && uncommitted.ok,
    rootDir,
    committed,
    uncommitted,
    durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
  }
}

export function formatContractChangeReport(result: ContractChangeRepoResult): string {
  const lines: string[] = []
  const sections = [result.committed, ...(result.uncommitted ? [result.uncommitted] : [])]
  for (const sec of sections) {
    if (sec.hits.length === 0) continue
    if (sec.trailerPresent) {
      lines.push(
        `contract-change [${sec.sourceLabel}]: PASS (${sec.hits.length} edit(s) authorized by trailer: Contract-change: ${sec.trailerValue})`,
      )
    } else if (sec.warned) {
      lines.push(
        `contract-change [${sec.sourceLabel}]: WARN (${sec.hits.length} uncommitted contract edit(s) — add a "Contract-change: <reason / A/B ledger ref>" trailer when committing):`,
      )
      for (const h of sec.hits) {
        const sym = h.symbol ? ` ${h.symbol}` : ''
        lines.push(`  ${h.file}:${h.line} [${h.kind}]${sym}: ${h.before} -> ${h.after}`)
      }
    } else {
      lines.push(
        `contract-change [${sec.sourceLabel}]: FAIL (${sec.hits.length} un-trailered contract edit(s) require a "Contract-change: <reason / A/B ledger ref>" commit trailer):`,
      )
      for (const h of sec.hits) {
        const sym = h.symbol ? ` ${h.symbol}` : ''
        lines.push(`  ${h.file}:${h.line} [${h.kind}]${sym}: ${h.before} -> ${h.after}`)
      }
    }
  }
  if (lines.length === 0) {
    lines.push(
      `contract-change: PASS (${result.committed.sourceLabel}, 0 un-trailered tunable/assert edits in ${result.durationMs}ms)`,
    )
  }
  return lines.join('\n')
}

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

const usage = `Kovo Hunter Contract-Change Diff Lint

Usage:
  node scripts/check-contract-change.ts [options]

Options:
  --base <ref>             Check committed diff <ref>..HEAD strictly (default: auto merge-base vs main)
  --check-head             Check HEAD~1..HEAD strictly when at base ref
  --staged                 Check staged diff (--cached) strictly
  --allow-uncommitted      Warn-only on uncommitted working tree edits (default)
  --strict-uncommitted     Fail on uncommitted working tree edits without --commit-msg
  --commit-msg <text>      Provide commit message text (for hooks / tests)
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
  let strictUncommitted = false
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
    if (arg === '--allow-uncommitted') { strictUncommitted = false; continue }
    if (arg === '--strict-uncommitted') { strictUncommitted = true; continue }
    if (arg === '--base') {
      const next = argv[i + 1]
      if (!next) { process.stderr.write('error: --base requires a git ref\n'); return 2 }
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

  const result = checkGitRepo({
    rootDir,
    baseRef,
    stagedOnly,
    checkHead,
    strictUncommitted,
    commitMessageOverride,
  })
  if (json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
  } else {
    const report = `${formatContractChangeReport(result)}\n`
    if (result.ok) process.stdout.write(report)
    else process.stderr.write(report)
  }
  return result.ok ? 0 : 1
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(resolve(process.argv[1])).href : false
if (isMain) {
  process.exit(main())
}
