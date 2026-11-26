#!/usr/bin/env node
/**
 * Monotone Function-Length & File-Growth Ratchet (`R2-22`, PR-22c; upgraded in `R3-10`).
 *
 * Fast (<2s), AST-accurate (parser-only `ts.createSourceFile`, no typechecker) analyzer over
 * `src/server/**` that supports:
 *   - Default warn-only mode (backward-compatible, exit 0)
 *   - `--strict`: fail (exit 1) if any file > 2000L or function > 150L
 *   - `--baseline`: monotone shrink-only ratchet against `scripts/size-baseline.json`:
 *       * Fails on any NEW over-limit file/function or line-count growth above baseline,
 *         UNLESS the commit range carries a `Split-ticket: <id>` trailer.
 *       * Fails (`prune-fail`) if any baselined file/function shrunk or dropped below limit
 *         without pruning the baseline via `--write-baseline`.
 *   - `--write-baseline`: strictly removal/shrink-only update of `scripts/size-baseline.json`
 *     (bootstraps when absent; refuses to add entries or raise counts when baseline exists).
 *
 * Usage:
 *   node scripts/check-function-growth.ts                     # warn-only (exit 0)
 *   node scripts/check-function-growth.ts --strict            # fail if any limit exceeded
 *   node scripts/check-function-growth.ts --baseline          # enforce monotone size ratchet
 *   node scripts/check-function-growth.ts --baseline --base HEAD~1
 *   node scripts/check-function-growth.ts --write-baseline    # shrink-only baseline prune
 *   node scripts/check-function-growth.ts --json              # machine-readable JSON output
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import ts from 'typescript'

export interface FunctionSpan {
  file: string
  name: string
  qualifiedName: string
  /** Canonical line-number-independent key used in `scripts/size-baseline.json`. */
  key: string
  startLine: number
  endLine: number
  lines: number
}

export interface FileSizeRecord {
  file: string
  lines: number
}

export interface SizeBaseline {
  version: 1
  dir: string
  maxFileLines: number
  maxFnLines: number
  filesOver4000Lines: number
  files: Record<string, number>
  functions: Record<string, number>
}

export interface SizeDeltaRecord {
  key: string
  baselineLines: number | null
  actualLines: number
  delta: number
}

export interface SizeBaselineEval {
  baselinePath: string
  baselineExists: boolean
  splitTickets: string[]
  allowedBySplitTicket: boolean
  grownFiles: SizeDeltaRecord[]
  grownFunctions: SizeDeltaRecord[]
  shrunkFiles: SizeDeltaRecord[]
  shrunkFunctions: SizeDeltaRecord[]
  unticketedGrowthCount: number
  unprunedShrinkCount: number
}

export interface FunctionGrowthOptions {
  dir?: string
  rootDir?: string
  maxFileLines?: number
  maxFnLines?: number
  top?: number
  strict?: boolean
  baseline?: boolean
  baselineFile?: string
  writeBaseline?: boolean
  baseRef?: string | null
  /** Programmatic override for commit messages (used in hermetic tests). */
  commitMessages?: string[]
}

export interface FunctionGrowthReport {
  ok: boolean
  strict: boolean
  baselineMode: boolean
  dir: string
  filesScanned: number
  functionsScanned: number
  maxFileLines: number
  maxFnLines: number
  filesOver4000Lines: number
  oversizedFiles: FileSizeRecord[]
  oversizedFunctions: FunctionSpan[]
  topFiles: FileSizeRecord[]
  topFunctions: FunctionSpan[]
  baselineEval?: SizeBaselineEval
  wroteBaselinePath?: string
  error?: string
  durationMs: number
}

export const DEFAULT_MAX_FILE_LINES = 2000
export const DEFAULT_MAX_FN_LINES = 150
export const DEFAULT_TOP_N = 15
export const DEFAULT_BASELINE_FILE = 'scripts/size-baseline.json'
export const SPLIT_TICKET_TRAILER_RE = /^\s*Split-ticket:\s*([A-Za-z0-9][A-Za-z0-9._:/-]{1,80})(?:\s+.*)?$/gim

function resolveFunctionName(node: ts.FunctionLikeDeclarationBase): string {
  if ('name' in node && node.name) {
    if (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name) || ts.isNumericLiteral(node.name)) {
      return node.name.text
    }
    if (ts.isPrivateIdentifier(node.name)) {
      return node.name.text
    }
  }
  if (ts.isConstructorDeclaration(node)) return 'constructor'
  const parent = node.parent
  if (parent) {
    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      return parent.name.text
    }
    if (ts.isPropertyAssignment(parent) && (ts.isIdentifier(parent.name) || ts.isStringLiteral(parent.name))) {
      return parent.name.text
    }
    if (ts.isPropertyDeclaration(parent) && (ts.isIdentifier(parent.name) || ts.isStringLiteral(parent.name))) {
      return parent.name.text
    }
    if (ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      return parent.left.getText()
    }
  }
  return '<anonymous>'
}

function resolveQualifiedName(node: ts.FunctionLikeDeclarationBase): string {
  const parts: string[] = [resolveFunctionName(node)]
  let cur: ts.Node | undefined = node.parent
  while (cur) {
    if (ts.isClassDeclaration(cur) || ts.isClassExpression(cur)) {
      if (cur.name && ts.isIdentifier(cur.name)) parts.unshift(cur.name.text)
    } else if (
      ts.isFunctionDeclaration(cur) ||
      ts.isMethodDeclaration(cur) ||
      ts.isConstructorDeclaration(cur) ||
      ts.isGetAccessorDeclaration(cur) ||
      ts.isSetAccessorDeclaration(cur)
    ) {
      parts.unshift(resolveFunctionName(cur))
    } else if (ts.isArrowFunction(cur) || ts.isFunctionExpression(cur)) {
      const parentName = resolveFunctionName(cur)
      if (parentName !== '<anonymous>') parts.unshift(parentName)
    }
    cur = cur.parent
  }
  return parts.join('.')
}

/**
 * Assign deterministic, order-preserving baseline keys to a list of functions.
 * Duplicate `(file, qualifiedName)` spans are ordered by descending line count (`name`, `name#2`, ...)
 * so shrinking or removing any instance never causes a false growth against the baseline.
 */
export function assignFunctionBaselineKeys(functions: FunctionSpan[]): void {
  const byGroup = new Map<string, FunctionSpan[]>()
  for (const fn of functions) {
    const baseKey = `${fn.file}::${fn.qualifiedName}`
    const list = byGroup.get(baseKey) ?? []
    list.push(fn)
    byGroup.set(baseKey, list)
  }
  for (const [baseKey, list] of byGroup) {
    list.sort((a, b) => b.lines - a.lines || a.startLine - b.startLine)
    for (let i = 0; i < list.length; i += 1) {
      list[i]!.key = i === 0 ? baseKey : `${baseKey}#${i + 1}`
    }
  }
}

/** Analyze a single TypeScript source file using parser-only `ts.createSourceFile`. */
export function analyzeSource(source: string, fileLabel: string): { lines: number; functions: FunctionSpan[] } {
  const sf = ts.createSourceFile(fileLabel, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const totalLines = source.length === 0 ? 0 : sf.getLineAndCharacterOfPosition(source.length).line + 1
  const functions: FunctionSpan[] = []

  const visit = (node: ts.Node) => {
    if (
      (ts.isFunctionDeclaration(node) ||
        ts.isMethodDeclaration(node) ||
        ts.isConstructorDeclaration(node) ||
        ts.isGetAccessorDeclaration(node) ||
        ts.isSetAccessorDeclaration(node) ||
        ts.isArrowFunction(node) ||
        ts.isFunctionExpression(node)) &&
      node.body
    ) {
      const startLine = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
      const endLine = sf.getLineAndCharacterOfPosition(node.getEnd()).line + 1
      const lines = endLine - startLine + 1
      const name = resolveFunctionName(node)
      const qualifiedName = resolveQualifiedName(node)
      functions.push({
        file: fileLabel,
        name,
        qualifiedName,
        key: `${fileLabel}::${qualifiedName}`,
        startLine,
        endLine,
        lines,
      })
    }
    ts.forEachChild(node, visit)
  }

  visit(sf)
  return { lines: totalLines, functions }
}

function collectTsFiles(dir: string): string[] {
  const results: string[] = []
  const visit = (current: string) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = join(current, entry.name)
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') continue
        visit(full)
      } else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
        results.push(full)
      }
    }
  }
  visit(dir)
  results.sort()
  return results
}

/** Extract all valid `Split-ticket: <id>` trailer values from commit message bodies. */
export function extractSplitTickets(commitMessages: readonly string[]): string[] {
  const tickets: string[] = []
  const seen = new Set<string>()
  for (const msg of commitMessages) {
    SPLIT_TICKET_TRAILER_RE.lastIndex = 0
    for (const match of msg.matchAll(SPLIT_TICKET_TRAILER_RE)) {
      const id = match[1]?.trim()
      if (id && !seen.has(id)) {
        seen.add(id)
        tickets.push(id)
      }
    }
  }
  return tickets
}

function readGitCommitMessages(rootDir: string, baseRef?: string | null): string[] {
  try {
    const args = baseRef
      ? ['-C', rootDir, 'log', '--format=%B%x00', `${baseRef}..HEAD`]
      : ['-C', rootDir, 'log', '-1', '--format=%B%x00']
    const raw = execFileSync('git', args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    return raw
      .split('\0')
      .map(s => s.trim())
      .filter(Boolean)
  } catch {
    return []
  }
}

export function loadSizeBaseline(baselinePath: string): SizeBaseline | null {
  if (!existsSync(baselinePath)) return null
  const parsed = JSON.parse(readFileSync(baselinePath, 'utf8')) as SizeBaseline
  return {
    version: 1,
    dir: parsed.dir ?? 'src/server',
    maxFileLines: parsed.maxFileLines ?? DEFAULT_MAX_FILE_LINES,
    maxFnLines: parsed.maxFnLines ?? DEFAULT_MAX_FN_LINES,
    filesOver4000Lines: parsed.filesOver4000Lines ?? 0,
    files: parsed.files ?? {},
    functions: parsed.functions ?? {},
  }
}

function sortedRecord(entries: Iterable<[string, number]>): Record<string, number> {
  const out: Record<string, number> = {}
  for (const [k, v] of [...entries].sort((a, b) => a[0].localeCompare(b[0]))) {
    out[k] = v
  }
  return out
}

export function buildSizeBaseline(input: {
  dir: string
  maxFileLines: number
  maxFnLines: number
  oversizedFiles: readonly FileSizeRecord[]
  oversizedFunctions: readonly FunctionSpan[]
}): SizeBaseline {
  const files = sortedRecord(input.oversizedFiles.map(f => [f.file, f.lines] as [string, number]))
  const functions = sortedRecord(input.oversizedFunctions.map(fn => [fn.key, fn.lines] as [string, number]))
  return {
    version: 1,
    dir: input.dir,
    maxFileLines: input.maxFileLines,
    maxFnLines: input.maxFnLines,
    filesOver4000Lines: input.oversizedFiles.filter(f => f.lines > 4000).length,
    files,
    functions,
  }
}

function compareAgainstBaseline(
  baseline: SizeBaseline,
  baselinePath: string,
  oversizedFiles: readonly FileSizeRecord[],
  oversizedFunctions: readonly FunctionSpan[],
  allFileLineMap: ReadonlyMap<string, number>,
  allFnLineMap: ReadonlyMap<string, number>,
  splitTickets: string[],
): SizeBaselineEval {
  const grownFiles: SizeDeltaRecord[] = []
  const shrunkFiles: SizeDeltaRecord[] = []
  const grownFunctions: SizeDeltaRecord[] = []
  const shrunkFunctions: SizeDeltaRecord[] = []

  const currentOversizedFileMap = new Map<string, number>()
  for (const f of oversizedFiles) {
    currentOversizedFileMap.set(f.file, f.lines)
    const baseLines = baseline.files[f.file]
    if (baseLines === undefined) {
      grownFiles.push({ key: f.file, baselineLines: null, actualLines: f.lines, delta: f.lines - baseline.maxFileLines })
    } else if (f.lines > baseLines) {
      grownFiles.push({ key: f.file, baselineLines: baseLines, actualLines: f.lines, delta: f.lines - baseLines })
    }
  }
  for (const [file, baseLines] of Object.entries(baseline.files)) {
    const actualOversized = currentOversizedFileMap.get(file)
    if (actualOversized === undefined) {
      const actualLines = allFileLineMap.get(file) ?? 0
      shrunkFiles.push({ key: file, baselineLines: baseLines, actualLines, delta: actualLines - baseLines })
    } else if (actualOversized < baseLines) {
      shrunkFiles.push({ key: file, baselineLines: baseLines, actualLines: actualOversized, delta: actualOversized - baseLines })
    }
  }

  const currentOversizedFnMap = new Map<string, number>()
  for (const fn of oversizedFunctions) {
    currentOversizedFnMap.set(fn.key, fn.lines)
    const baseLines = baseline.functions[fn.key]
    if (baseLines === undefined) {
      grownFunctions.push({ key: fn.key, baselineLines: null, actualLines: fn.lines, delta: fn.lines - baseline.maxFnLines })
    } else if (fn.lines > baseLines) {
      grownFunctions.push({ key: fn.key, baselineLines: baseLines, actualLines: fn.lines, delta: fn.lines - baseLines })
    }
  }
  for (const [fnKey, baseLines] of Object.entries(baseline.functions)) {
    const actualOversized = currentOversizedFnMap.get(fnKey)
    if (actualOversized === undefined) {
      const actualLines = allFnLineMap.get(fnKey) ?? 0
      shrunkFunctions.push({ key: fnKey, baselineLines: baseLines, actualLines, delta: actualLines - baseLines })
    } else if (actualOversized < baseLines) {
      shrunkFunctions.push({ key: fnKey, baselineLines: baseLines, actualLines: actualOversized, delta: actualOversized - baseLines })
    }
  }

  grownFiles.sort((a, b) => b.delta - a.delta || a.key.localeCompare(b.key))
  grownFunctions.sort((a, b) => b.delta - a.delta || a.key.localeCompare(b.key))
  shrunkFiles.sort((a, b) => a.key.localeCompare(b.key))
  shrunkFunctions.sort((a, b) => a.key.localeCompare(b.key))

  const totalGrowth = grownFiles.length + grownFunctions.length
  const allowedBySplitTicket = totalGrowth > 0 && splitTickets.length > 0
  const unticketedGrowthCount = allowedBySplitTicket ? 0 : totalGrowth
  const unprunedShrinkCount = shrunkFiles.length + shrunkFunctions.length

  return {
    baselinePath,
    baselineExists: true,
    splitTickets,
    allowedBySplitTicket,
    grownFiles,
    grownFunctions,
    shrunkFiles,
    shrunkFunctions,
    unticketedGrowthCount,
    unprunedShrinkCount,
  }
}

/** Run the warn-only, `--strict`, `--baseline`, or `--write-baseline` function-length and file-growth ratchet. */
export function runFunctionGrowthCheck(options: FunctionGrowthOptions = {}): FunctionGrowthReport {
  const t0 = Date.now()
  const rootDir = resolve(options.rootDir ?? join(fileURLToPath(import.meta.url), '../..'))
  const targetDir = resolve(rootDir, options.dir ?? 'src/server')
  const relDir = relative(rootDir, targetDir).replace(/\\/g, '/') || '.'
  const maxFileLines = options.maxFileLines ?? DEFAULT_MAX_FILE_LINES
  const maxFnLines = options.maxFnLines ?? DEFAULT_MAX_FN_LINES
  const top = Math.max(1, options.top ?? DEFAULT_TOP_N)
  const strict = Boolean(options.strict)
  const baselineMode = Boolean(options.baseline || options.writeBaseline)
  const baselinePath = resolve(rootDir, options.baselineFile ?? DEFAULT_BASELINE_FILE)

  const files = collectTsFiles(targetDir)
  const fileRecords: FileSizeRecord[] = []
  const allFunctions: FunctionSpan[] = []
  const allFileLineMap = new Map<string, number>()

  for (const absPath of files) {
    if (!statSync(absPath).isFile()) continue
    const rel = relative(rootDir, absPath).replace(/\\/g, '/')
    const source = readFileSync(absPath, 'utf8')
    const { lines, functions } = analyzeSource(source, rel)
    fileRecords.push({ file: rel, lines })
    allFileLineMap.set(rel, lines)
    for (const fn of functions) allFunctions.push(fn)
  }

  fileRecords.sort((a, b) => b.lines - a.lines || a.file.localeCompare(b.file))
  const oversizedFiles = fileRecords.filter(f => f.lines > maxFileLines)
  const oversizedFunctions = allFunctions.filter(fn => fn.lines > maxFnLines)
  assignFunctionBaselineKeys(oversizedFunctions)
  oversizedFunctions.sort((a, b) => b.lines - a.lines || a.file.localeCompare(b.file) || a.startLine - b.startLine)
  allFunctions.sort((a, b) => b.lines - a.lines || a.file.localeCompare(b.file) || a.startLine - b.startLine)

  const allFnLineMap = new Map<string, number>()
  for (const fn of allFunctions) {
    const prev = allFnLineMap.get(fn.key) ?? 0
    if (fn.lines > prev) allFnLineMap.set(fn.key, fn.lines)
  }

  const filesOver4000Lines = oversizedFiles.filter(f => f.lines > 4000).length

  if (options.writeBaseline) {
    const existing = loadSizeBaseline(baselinePath)
    const nextBaseline = buildSizeBaseline({
      dir: relDir,
      maxFileLines,
      maxFnLines,
      oversizedFiles,
      oversizedFunctions,
    })
    if (existing) {
      const evalRes = compareAgainstBaseline(
        existing,
        relative(rootDir, baselinePath).replace(/\\/g, '/'),
        oversizedFiles,
        oversizedFunctions,
        allFileLineMap,
        allFnLineMap,
        [],
      )
      if (evalRes.grownFiles.length > 0 || evalRes.grownFunctions.length > 0) {
        return {
          ok: false,
          strict,
          baselineMode: true,
          dir: relDir,
          filesScanned: fileRecords.length,
          functionsScanned: allFunctions.length,
          maxFileLines,
          maxFnLines,
          filesOver4000Lines,
          oversizedFiles,
          oversizedFunctions,
          topFiles: fileRecords.slice(0, top),
          topFunctions: allFunctions.slice(0, top),
          baselineEval: evalRes,
          error:
            `Refusing --write-baseline: baseline is strictly shrink/removal-only, but ` +
            `${evalRes.grownFiles.length} file(s) and ${evalRes.grownFunctions.length} function(s) grew above baseline.`,
          durationMs: Date.now() - t0,
        }
      }
    }
    writeFileSync(baselinePath, `${JSON.stringify(nextBaseline, null, 2)}\n`, 'utf8')
    return {
      ok: true,
      strict,
      baselineMode: true,
      dir: relDir,
      filesScanned: fileRecords.length,
      functionsScanned: allFunctions.length,
      maxFileLines,
      maxFnLines,
      filesOver4000Lines,
      oversizedFiles,
      oversizedFunctions,
      topFiles: fileRecords.slice(0, top),
      topFunctions: allFunctions.slice(0, top),
      wroteBaselinePath: relative(rootDir, baselinePath).replace(/\\/g, '/'),
      durationMs: Date.now() - t0,
    }
  }

  if (options.baseline) {
    const existing = loadSizeBaseline(baselinePath)
    const relBase = relative(rootDir, baselinePath).replace(/\\/g, '/')
    if (!existing) {
      return {
        ok: false,
        strict,
        baselineMode: true,
        dir: relDir,
        filesScanned: fileRecords.length,
        functionsScanned: allFunctions.length,
        maxFileLines,
        maxFnLines,
        filesOver4000Lines,
        oversizedFiles,
        oversizedFunctions,
        topFiles: fileRecords.slice(0, top),
        topFunctions: allFunctions.slice(0, top),
        baselineEval: {
          baselinePath: relBase,
          baselineExists: false,
          splitTickets: [],
          allowedBySplitTicket: false,
          grownFiles: [],
          grownFunctions: [],
          shrunkFiles: [],
          shrunkFunctions: [],
          unticketedGrowthCount: 0,
          unprunedShrinkCount: 0,
        },
        error: `Size baseline not found at ${relBase}. Run --write-baseline to initialize.`,
        durationMs: Date.now() - t0,
      }
    }
    const commitMessages = options.commitMessages ?? readGitCommitMessages(rootDir, options.baseRef)
    const splitTickets = extractSplitTickets(commitMessages)
    const baselineEval = compareAgainstBaseline(
      existing,
      relBase,
      oversizedFiles,
      oversizedFunctions,
      allFileLineMap,
      allFnLineMap,
      splitTickets,
    )
    const ok = baselineEval.unticketedGrowthCount === 0 && baselineEval.unprunedShrinkCount === 0
    return {
      ok,
      strict,
      baselineMode: true,
      dir: relDir,
      filesScanned: fileRecords.length,
      functionsScanned: allFunctions.length,
      maxFileLines,
      maxFnLines,
      filesOver4000Lines,
      oversizedFiles,
      oversizedFunctions,
      topFiles: fileRecords.slice(0, top),
      topFunctions: allFunctions.slice(0, top),
      baselineEval,
      durationMs: Date.now() - t0,
    }
  }

  const ok = strict ? oversizedFiles.length === 0 && oversizedFunctions.length === 0 : true
  return {
    ok,
    strict,
    baselineMode,
    dir: relDir,
    filesScanned: fileRecords.length,
    functionsScanned: allFunctions.length,
    maxFileLines,
    maxFnLines,
    filesOver4000Lines,
    oversizedFiles,
    oversizedFunctions,
    topFiles: fileRecords.slice(0, top),
    topFunctions: allFunctions.slice(0, top),
    durationMs: Date.now() - t0,
  }
}

function parseArgs(argv: string[]): FunctionGrowthOptions & { json: boolean } {
  const opts: FunctionGrowthOptions & { json: boolean } = { json: false }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--strict') opts.strict = true
    else if (arg === '--baseline') {
      opts.baseline = true
      const next = argv[i + 1]
      if (next && !next.startsWith('--') && next.endsWith('.json')) {
        opts.baselineFile = argv[++i]!
      }
    } else if (arg === '--baseline-file' && argv[i + 1]) {
      opts.baseline = true
      opts.baselineFile = argv[++i]!
    } else if (arg === '--write-baseline') {
      opts.writeBaseline = true
      const next = argv[i + 1]
      if (next && !next.startsWith('--') && next.endsWith('.json')) {
        opts.baselineFile = argv[++i]!
      }
    } else if (arg === '--base' && argv[i + 1]) opts.baseRef = argv[++i]!
    else if (arg === '--root' && argv[i + 1]) opts.rootDir = argv[++i]!
    else if (arg === '--json') opts.json = true
    else if (arg === '--dir' && argv[i + 1]) opts.dir = argv[++i]!
    else if (arg === '--max-file-lines' && argv[i + 1]) opts.maxFileLines = Number(argv[++i]!)
    else if (arg === '--max-fn-lines' && argv[i + 1]) opts.maxFnLines = Number(argv[++i]!)
    else if (arg === '--top' && argv[i + 1]) opts.top = Number(argv[++i]!)
  }
  return opts
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2))
  const report = runFunctionGrowthCheck(opts)
  if (opts.json) {
    console.log(JSON.stringify(report, null, 2))
  } else if (report.wroteBaselinePath) {
    console.log(
      `check-function-growth [WRITE-BASELINE] PASS (${report.durationMs}ms): ` +
        `wrote ${report.wroteBaselinePath} (oversizedFiles=${report.oversizedFiles.length}, ` +
        `filesOver4000=${report.filesOver4000Lines}, oversizedFunctions=${report.oversizedFunctions.length})`,
    )
  } else if (report.baselineMode && report.baselineEval) {
    const ev = report.baselineEval
    const status = report.ok ? 'PASS' : 'FAIL'
    console.log(
      `check-function-growth [BASELINE] ${status} (${report.durationMs}ms): ` +
        `scanned ${report.filesScanned} files, ${report.functionsScanned} functions in ${report.dir} ` +
        `(oversizedFiles=${report.oversizedFiles.length}, filesOver4000=${report.filesOver4000Lines}, ` +
        `oversizedFunctions=${report.oversizedFunctions.length}, ` +
        `unticketedGrowth=${ev.unticketedGrowthCount}, unprunedShrink=${ev.unprunedShrinkCount}` +
        `${ev.allowedBySplitTicket ? `, splitTickets=[${ev.splitTickets.join(',')}]` : ''})`,
    )
    if (report.error) console.error(`  ERROR: ${report.error}`)
    if (ev.grownFiles.length > 0) {
      const tag = ev.allowedBySplitTicket ? 'TICKETED-GROWTH' : 'FAIL-GROWTH'
      console.log(`\nOver-limit file growth (${ev.grownFiles.length}):`)
      for (const d of ev.grownFiles) {
        const base = d.baselineLines === null ? `NEW(>${report.maxFileLines})` : String(d.baselineLines)
        console.log(`  ${tag}  ${d.key}: ${base} -> ${d.actualLines} (+${d.delta}L)`)
      }
    }
    if (ev.grownFunctions.length > 0) {
      const tag = ev.allowedBySplitTicket ? 'TICKETED-GROWTH' : 'FAIL-GROWTH'
      console.log(`\nOver-limit function growth (${ev.grownFunctions.length}):`)
      for (const d of ev.grownFunctions) {
        const base = d.baselineLines === null ? `NEW(>${report.maxFnLines})` : String(d.baselineLines)
        console.log(`  ${tag}  ${d.key}: ${base} -> ${d.actualLines} (+${d.delta}L)`)
      }
    }
    if (ev.shrunkFiles.length > 0 || ev.shrunkFunctions.length > 0) {
      console.log(
        `\nBaselined items shrunk without pruning (run \`node scripts/check-function-growth.ts --write-baseline\`):`,
      )
      for (const d of ev.shrunkFiles) {
        console.log(`  PRUNE-FAIL  file ${d.key}: ${d.baselineLines} -> ${d.actualLines} (${d.delta}L)`)
      }
      for (const d of ev.shrunkFunctions) {
        console.log(`  PRUNE-FAIL  fn ${d.key}: ${d.baselineLines} -> ${d.actualLines} (${d.delta}L)`)
      }
    }
  } else {
    const modeLabel = report.strict ? 'STRICT' : 'WARN-ONLY'
    const status = report.ok ? 'PASS' : 'FAIL'
    console.log(
      `check-function-growth [${modeLabel}] ${status} (${report.durationMs}ms): ` +
        `scanned ${report.filesScanned} files, ${report.functionsScanned} functions in ${report.dir} ` +
        `(oversized files >${report.maxFileLines}L: ${report.oversizedFiles.length}, ` +
        `oversized functions >${report.maxFnLines}L: ${report.oversizedFunctions.length})`,
    )
    if (report.oversizedFiles.length > 0) {
      console.log(`\nTop oversized files (>${report.maxFileLines} lines):`)
      for (const f of report.oversizedFiles.slice(0, opts.top ?? DEFAULT_TOP_N)) {
        console.log(`  WARN  ${String(f.lines).padStart(5)} lines  ${f.file}`)
      }
    }
    if (report.oversizedFunctions.length > 0) {
      console.log(`\nTop oversized functions (>${report.maxFnLines} lines):`)
      for (const fn of report.oversizedFunctions.slice(0, opts.top ?? DEFAULT_TOP_N)) {
        console.log(`  WARN  ${String(fn.lines).padStart(5)} lines  ${fn.file}:${fn.startLine}-${fn.endLine}  ${fn.name}()`)
      }
    }
  }
  if (!report.ok) process.exit(1)
}

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
if (isMain) {
  main()
}
