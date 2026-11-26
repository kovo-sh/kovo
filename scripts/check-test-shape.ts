#!/usr/bin/env node
/**
 * Test-Shape Ratchet Lint (`R3-06`, plans/claude_quality_3.md §6).
 *
 * Fast (<1s), parser-only TypeScript AST (`ts.createSourceFile`) check over `tests/**\/*.test.ts`
 * that flags tests reading production source files (`readFileSync(src/**)` / `readFile(src/**)`)
 * as raw text and asserting implementation internals with regex (`assert.match` / `assert.doesNotMatch`)
 * instead of exercising behavioral entry points.
 *
 * Strictly non-increasing monotone ratchet:
 *   - Fails (exit 1) if ANY unlisted test file introduces `readFileSync(src/**)` + `assert.match`/`assert.doesNotMatch`.
 *   - Fails (exit 1) if ANY baselined test file increases its source-text regex assertion count above baseline.
 *   - Fails (exit 1) if total source-text regex assertions or affected file count exceed baseline.
 *   - Passes (exit 0) at or below baseline, reporting any reduced counts so the baseline can be ratcheted down.
 *
 * Usage:
 *   node scripts/check-test-shape.ts [--root <dir>] [--dir tests] [--json] [--print-baseline] [-h|--help]
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, posix, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import ts from 'typescript'

export interface TestShapeRegexHit {
  file: string
  line: number
  method: 'match' | 'doesNotMatch'
  excerpt: string
}

export interface TestFileShapeReport {
  file: string
  srcTextReadLines: number[]
  sourceRegexAssertCount: number
  sourceRegexHits: TestShapeRegexHit[]
  locPinCount: number
}

export interface TestShapeRegression {
  file: string
  kind: 'new_file' | 'count_increased' | 'total_exceeded' | 'file_count_exceeded'
  baseline: number
  actual: number
  detail: string
}

export interface TestShapeReduction {
  file: string
  baseline: number
  actual: number
}

export interface TestShapeScanOptions {
  rootDir?: string
  dir?: string
  baselineByFile?: Readonly<Record<string, number>>
  baselineTotal?: number
  baselineFiles?: number
}

export interface TestShapeScanResult {
  ok: boolean
  rootDir: string
  dir: string
  filesScanned: number
  filesReadingSrcText: number
  filesWithSourceRegexAsserts: number
  totalSourceRegexAsserts: number
  totalLocPins: number
  baselineFiles: number
  baselineTotal: number
  countsByFile: Record<string, number>
  flaggedFiles: TestFileShapeReport[]
  regressions: TestShapeRegression[]
  reductions: TestShapeReduction[]
  durationMs: number
}

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const EXCLUDED_DIRS = new Set(['node_modules', '.git', 'dist', '.output', 'coverage'])
const SRC_PATH_LITERAL_RE = /(?:^|[/\\])src(?:[/\\]|$)/
const TESTS_PATH_LITERAL_RE = /(?:^|[/\\])tests(?:[/\\]|$)/

/**
 * Monotone per-file baseline of `assert.match` / `assert.doesNotMatch` calls in test files that
 * read `src/**` source text (`readFileSync`/`readFile`). Counts may ONLY decrease over time.
 */
export const BASELINE_SOURCE_TEXT_REGEX_ASSERTS: Readonly<Record<string, number>> = Object.freeze({
  'tests/agent-contract.test.ts': 5,
  'tests/arch-a1-engine.test.ts': 2,
  'tests/arch-b2-exec-cleanup.test.ts': 1,
  'tests/arch-c1-verify-kernel.test.ts': 11,
  'tests/arch-c3-split.test.ts': 2,
  'tests/arch-c3-store-repos.test.ts': 5,
  'tests/arch-o4-clock-stream.test.ts': 6,
  'tests/arch-p2-patch-gate6.test.ts': 8,
  'tests/arch-p3-cut3-diet.test.ts': 15,
  'tests/arch-u2-control-plane.test.ts': 26,
  'tests/audit-compute-lab-fixes.test.ts': 2,
  'tests/audit-proof-a.test.ts': 9,
  'tests/dedupe-veto.test.ts': 4,
  'tests/findings-view-conformance.test.ts': 2,
  'tests/fix-m2-budgets-seal.test.ts': 2,
  'tests/fix-m2-edge-binding.test.ts': 5,
  'tests/fix-m2-prompt-skills.test.ts': 21,
  'tests/fix-run-header-qa.test.ts': 4,
  'tests/fix-signed-url-oracle.test.ts': 2,
  'tests/movea-oracle-invar.test.ts': 1,
  'tests/movea-waveb-v8.test.ts': 3,
  'tests/path-parity.test.ts': 3,
  'tests/r2-22-dedup-perms.test.ts': 3,
  'tests/r2-ws14-actor-wedges.test.ts': 3,
  'tests/r2-ws15-verify-ux.test.ts': 5,
  'tests/r2-ws18-dood-worker.test.ts': 1,
  'tests/r3-browser-session.test.ts': 5,
  'tests/r3-chromium-sandbox.test.ts': 6,
  'tests/r3-graph-host.test.ts': 2,
  'tests/r3-node-hardening.test.ts': 15,
  'tests/r3-scope-ranking.test.ts': 4,
  'tests/r3-ui-curl.test.ts': 2,
  'tests/r4-gate6-retest.test.ts': 4,
  'tests/r4-host-compute.test.ts': 7,
  'tests/r4-orchestration-lifecycle.test.ts': 4,
  'tests/r4-repo-isolation.test.ts': 2,
  'tests/step-status-agreement.test.ts': 2,
  'tests/sys-contract-canary.test.ts': 13,
  'tests/sys-q2-repo-tools.test.ts': 15,
  'tests/sys-q7-ui-reports.test.ts': 21,
  'tests/sys-q8-patch-retest.test.ts': 3,
  'tests/t1-killswitch-nav.test.ts': 8,
  'tests/t2-composite-hydrate.test.ts': 5,
  'tests/tw4-foundation.test.ts': 30,
  'tests/universal-browser-auth.test.ts': 10,
  'tests/ux-consent-sticky.test.ts': 4,
  'tests/ux-edit-sources-repos.test.ts': 11,
  'tests/ux-round0-stepper.test.ts': 17,
  'tests/ux-run-leases-rename.test.ts': 19,
  'tests/ux-subdomain-discovery.test.ts': 3,
  'tests/ux-wave-run-controls.test.ts': 17,
  'tests/ux-wave-settings-auth.test.ts': 11,
  'tests/ux-zero-persona-warn.test.ts': 2,
  'tests/v4-e2e-tiers.test.ts': 44,
  'tests/v4-m3-worker-sast-templates.test.ts': 8,
  'tests/v5-m1-wiring-correctness.test.ts': 23,
  'tests/v5-m5-board-execution.test.ts': 7,
  'tests/v5-security-lab2.test.ts': 3,
  'tests/v5-security-repo.test.ts': 6,
  'tests/v6-coordinator.test.ts': 1,
  'tests/v6-floor.test.ts': 4,
  'tests/v7-confirm-consistency.test.ts': 3,
  'tests/v7-proofreceipt.test.ts': 9,
  'tests/v8-composite-receipt.test.ts': 2,
  'tests/v8-invariant-synthesizer.test.ts': 1,
  'tests/v8-m2-soundness-fixes.test.ts': 3,
  'tests/v8-patch-retest.test.ts': 9,
  'tests/v8-q26-provenance-soundness.test.ts': 6,
  'tests/v8-q27-fix-binding.test.ts': 13,
  'tests/v8-q27-fix-sdk-ergo.test.ts': 3,
  'tests/v8-q32-stub-telemetry.test.ts': 4,
  'tests/v8-q34-verify-binding.test.ts': 9,
  'tests/v8-sdk-adoption.test.ts': 8,
  'tests/v8-sdk-strict-camel.test.ts': 4,
  'tests/v8-wire-graph.test.ts': 1,
  'tests/wavea-route-template.test.ts': 3,
})

export const BASELINE_TOTAL_SOURCE_TEXT_REGEX_ASSERTS: number = Object.values(
  BASELINE_SOURCE_TEXT_REGEX_ASSERTS,
).reduce((sum, n) => sum + n, 0)

export const BASELINE_FILES_WITH_SOURCE_TEXT_REGEX_ASSERTS: number = Object.keys(
  BASELINE_SOURCE_TEXT_REGEX_ASSERTS,
).length

function toPosix(p: string): string {
  return sep === '/' ? p : p.split(sep).join(posix.sep)
}

function collectTestFiles(rootDir: string, relDir: string): string[] {
  const startAbs = join(rootDir, relDir)
  if (!existsSync(startAbs)) return []
  const out: string[] = []
  const walk = (dirAbs: string) => {
    const entries = readdirSync(dirAbs, { withFileTypes: true })
    entries.sort((a, b) => a.name.localeCompare(b.name))
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue
      const full = join(dirAbs, entry.name)
      if (entry.isDirectory()) {
        if (EXCLUDED_DIRS.has(entry.name)) continue
        walk(full)
      } else if (entry.isFile() && entry.name.endsWith('.test.ts')) {
        out.push(toPosix(relative(rootDir, full)))
      }
    }
  }
  walk(startAbs)
  return out
}

function exprReferencesSrcPath(node: ts.Node, sf: ts.SourceFile): boolean {
  let sawSrc = false
  let sawOnlyTests = false
  const visit = (n: ts.Node) => {
    if (sawSrc) return
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) {
      const text = n.text.replace(/\\/g, '/')
      if (text === 'src' || SRC_PATH_LITERAL_RE.test(text)) {
        if (!TESTS_PATH_LITERAL_RE.test(text) || text.includes('/src/')) {
          sawSrc = true
          return
        }
      } else if (TESTS_PATH_LITERAL_RE.test(text)) {
        sawOnlyTests = true
      }
    } else if (ts.isTemplateExpression(n)) {
      const head = n.head.text.replace(/\\/g, '/')
      if (SRC_PATH_LITERAL_RE.test(head)) {
        sawSrc = true
        return
      }
      for (const span of n.templateSpans) {
        const lit = span.literal.text.replace(/\\/g, '/')
        if (SRC_PATH_LITERAL_RE.test(lit)) {
          sawSrc = true
          return
        }
        visit(span.expression)
      }
      return
    }
    ts.forEachChild(n, visit)
  }
  visit(node)
  if (sawSrc) return true
  if (sawOnlyTests) return false
  const raw = node.getText(sf)
  return /\b(?:SRC_DIR|SERVER_DIR|SRC_ROOT|SERVER_ROOT|SOURCE_PATH)\b/.test(raw)
}

function isReadFileCall(expr: ts.Expression): boolean {
  if (ts.isIdentifier(expr)) {
    return expr.text === 'readFileSync' || expr.text === 'readFile'
  }
  if (ts.isPropertyAccessExpression(expr)) {
    return expr.name.text === 'readFileSync' || expr.name.text === 'readFile'
  }
  return false
}

function getAssertRegexMethod(expr: ts.Expression): 'match' | 'doesNotMatch' | null {
  if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.expression)) {
    if (expr.expression.text === 'assert' && (expr.name.text === 'match' || expr.name.text === 'doesNotMatch')) {
      return expr.name.text
    }
  }
  return null
}

function isLineSplitLengthExpr(node: ts.PropertyAccessExpression, sf: ts.SourceFile): boolean {
  if (node.name.text !== 'length') return false
  if (!ts.isCallExpression(node.expression)) return false
  const callee = node.expression.expression
  if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== 'split') return false
  const firstArg = node.expression.arguments[0]
  if (!firstArg) return false
  const argText = firstArg.getText(sf)
  return argText === "'\\n'" || argText === '"\\n"' || /\\n/.test(argText)
}

/**
 * Analyze a single TypeScript test file using parser-only AST (`ts.createSourceFile`).
 */
export function analyzeTestFileShape(sourceText: string, fileLabel: string): TestFileShapeReport {
  const sf = ts.createSourceFile(fileLabel, sourceText, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const srcPathVars = new Set<string>()
  const srcTextReadLines: number[] = []
  const regexCalls: TestShapeRegexHit[] = []
  let locPinCount = 0

  // Pass 1: collect local variables initialized with a `src/` path expression.
  const collectPathVars = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      if (exprReferencesSrcPath(node.initializer, sf)) {
        srcPathVars.add(node.name.text)
      }
    }
    ts.forEachChild(node, collectPathVars)
  }
  collectPathVars(sf)

  const referencesSrcArg = (arg: ts.Expression): boolean => {
    if (exprReferencesSrcPath(arg, sf)) return true
    let found = false
    const checkIds = (n: ts.Node) => {
      if (found) return
      if (ts.isIdentifier(n) && srcPathVars.has(n.text)) {
        found = true
        return
      }
      ts.forEachChild(n, checkIds)
    }
    checkIds(arg)
    return found
  }

  // Pass 2: collect readFileSync(src/**), assert.match / assert.doesNotMatch, and LOC pins.
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      if (isReadFileCall(node.expression) && node.arguments.length > 0 && referencesSrcArg(node.arguments[0]!)) {
        const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
        srcTextReadLines.push(line)
      } else {
        const method = getAssertRegexMethod(node.expression)
        if (method) {
          const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
          const excerpt = node.getText(sf).replace(/\s+/g, ' ').trim().slice(0, 120)
          regexCalls.push({ file: fileLabel, line, method, excerpt })
        }
      }
    } else if (ts.isPropertyAccessExpression(node) && isLineSplitLengthExpr(node, sf)) {
      locPinCount += 1
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)

  const readsSrcText = srcTextReadLines.length > 0
  return {
    file: fileLabel,
    srcTextReadLines,
    sourceRegexAssertCount: readsSrcText ? regexCalls.length : 0,
    sourceRegexHits: readsSrcText ? regexCalls : [],
    locPinCount: readsSrcText ? locPinCount : 0,
  }
}

export function scanTestShape(options: TestShapeScanOptions = {}): TestShapeScanResult {
  const t0 = Date.now()
  const rootDir = resolve(options.rootDir ?? REPO_ROOT)
  const dir = options.dir ?? 'tests'
  const baselineByFile = options.baselineByFile ?? BASELINE_SOURCE_TEXT_REGEX_ASSERTS
  const baselineTotal =
    options.baselineTotal ?? Object.values(baselineByFile).reduce((sum, n) => sum + n, 0)
  const baselineFiles = options.baselineFiles ?? Object.keys(baselineByFile).length

  const files = collectTestFiles(rootDir, dir)
  const countsByFile: Record<string, number> = {}
  const flaggedFiles: TestFileShapeReport[] = []
  let filesReadingSrcText = 0
  let totalSourceRegexAsserts = 0
  let totalLocPins = 0

  for (const rel of files) {
    const abs = join(rootDir, rel)
    const sourceText = readFileSync(abs, 'utf8')
    const report = analyzeTestFileShape(sourceText, rel)
    if (report.srcTextReadLines.length > 0) {
      filesReadingSrcText += 1
      totalLocPins += report.locPinCount
    }
    if (report.sourceRegexAssertCount > 0) {
      countsByFile[rel] = report.sourceRegexAssertCount
      flaggedFiles.push(report)
      totalSourceRegexAsserts += report.sourceRegexAssertCount
    }
  }

  const regressions: TestShapeRegression[] = []
  const reductions: TestShapeReduction[] = []

  const allFiles = new Set([...Object.keys(baselineByFile), ...Object.keys(countsByFile)])
  for (const file of [...allFiles].sort()) {
    const expected = baselineByFile[file] ?? 0
    const actual = countsByFile[file] ?? 0
    if (expected === 0 && actual > 0) {
      regressions.push({
        file,
        kind: 'new_file',
        baseline: 0,
        actual,
        detail: `${file}: introduced ${actual} source-text regex assertion(s) over src/**; test behavioral entry points instead`,
      })
    } else if (actual > expected) {
      regressions.push({
        file,
        kind: 'count_increased',
        baseline: expected,
        actual,
        detail: `${file}: source-text regex assertions grew (${actual} > baseline ${expected})`,
      })
    } else if (actual < expected) {
      reductions.push({ file, baseline: expected, actual })
    }
  }

  if (totalSourceRegexAsserts > baselineTotal) {
    regressions.push({
      file: '<total>',
      kind: 'total_exceeded',
      baseline: baselineTotal,
      actual: totalSourceRegexAsserts,
      detail: `total source-text regex assertions grew (${totalSourceRegexAsserts} > baseline ${baselineTotal})`,
    })
  }
  if (flaggedFiles.length > baselineFiles) {
    regressions.push({
      file: '<files>',
      kind: 'file_count_exceeded',
      baseline: baselineFiles,
      actual: flaggedFiles.length,
      detail: `files with source-text regex assertions grew (${flaggedFiles.length} > baseline ${baselineFiles})`,
    })
  }

  return {
    ok: regressions.length === 0,
    rootDir,
    dir,
    filesScanned: files.length,
    filesReadingSrcText,
    filesWithSourceRegexAsserts: flaggedFiles.length,
    totalSourceRegexAsserts,
    totalLocPins,
    baselineFiles,
    baselineTotal,
    countsByFile,
    flaggedFiles,
    regressions,
    reductions,
    durationMs: Date.now() - t0,
  }
}

function formatBaselineConstant(countsByFile: Record<string, number>): string {
  const keys = Object.keys(countsByFile).sort()
  const lines = ['export const BASELINE_SOURCE_TEXT_REGEX_ASSERTS: Readonly<Record<string, number>> = Object.freeze({']
  for (const k of keys) {
    lines.push(`  ${JSON.stringify(k)}: ${countsByFile[k]},`)
  }
  lines.push('})')
  return lines.join('\n')
}

function runCli(): void {
  const args = process.argv.slice(2)
  let rootDir = REPO_ROOT
  let dir = 'tests'
  let jsonOut = false
  let printBaseline = false

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!
    if (arg === '--root' && args[i + 1]) {
      rootDir = resolve(args[++i]!)
    } else if (arg === '--dir' && args[i + 1]) {
      dir = args[++i]!
    } else if (arg === '--json') {
      jsonOut = true
    } else if (arg === '--print-baseline') {
      printBaseline = true
    } else if (arg === '-h' || arg === '--help') {
      console.log(
        'Usage: node scripts/check-test-shape.ts [--root <dir>] [--dir tests] [--json] [--print-baseline]',
      )
      process.exit(0)
    } else {
      console.error(`Unknown option: ${arg}`)
      process.exit(2)
    }
  }

  const res = scanTestShape({ rootDir, dir })
  if (printBaseline) {
    console.log(formatBaselineConstant(res.countsByFile))
    process.exit(0)
  }
  if (jsonOut) {
    console.log(JSON.stringify(res, null, 2))
  } else if (res.ok) {
    const redNote = res.reductions.length > 0
      ? ` (${res.reductions.length} file(s) improved below baseline — run --print-baseline to tighten)`
      : ''
    console.log(
      `check-test-shape: PASS (scanned=${res.filesScanned}, srcTextFiles=${res.filesReadingSrcText}, flaggedFiles=${res.filesWithSourceRegexAsserts}/${res.baselineFiles}, regexAsserts=${res.totalSourceRegexAsserts}/${res.baselineTotal}, locPins=${res.totalLocPins}, ${res.durationMs}ms)${redNote}`,
    )
  } else {
    console.error(
      `check-test-shape: FAIL (flaggedFiles=${res.filesWithSourceRegexAsserts}/${res.baselineFiles}, regexAsserts=${res.totalSourceRegexAsserts}/${res.baselineTotal}, regressions=${res.regressions.length}, ${res.durationMs}ms):`,
    )
    for (const r of res.regressions) {
      console.error(`  - ${r.detail}`)
    }
  }
  process.exit(res.ok ? 0 : 1)
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  runCli()
}
