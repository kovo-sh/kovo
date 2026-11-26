#!/usr/bin/env node
/**
 * Warn-only Function-Length & File-Growth Ratchet (`R2-22`, PR-22c).
 *
 * Fast (<2s), AST-accurate (parser-only `ts.createSourceFile`, no typechecker) analyzer over
 * `src/server/**` that tracks god-file and god-function growth without blocking merges by default.
 *
 * Usage:
 *   node scripts/check-function-growth.ts                     # warn-only (exit 0)
 *   node scripts/check-function-growth.ts --strict            # fail (exit 1) if any limit exceeded
 *   node scripts/check-function-growth.ts --json              # machine-readable JSON output
 *   node scripts/check-function-growth.ts --dir src/server --max-file-lines 2000 --max-fn-lines 150 --top 15
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import ts from 'typescript'

export interface FunctionSpan {
  file: string
  name: string
  startLine: number
  endLine: number
  lines: number
}

export interface FileSizeRecord {
  file: string
  lines: number
}

export interface FunctionGrowthOptions {
  dir?: string
  rootDir?: string
  maxFileLines?: number
  maxFnLines?: number
  top?: number
  strict?: boolean
}

export interface FunctionGrowthReport {
  ok: boolean
  strict: boolean
  dir: string
  filesScanned: number
  functionsScanned: number
  maxFileLines: number
  maxFnLines: number
  oversizedFiles: FileSizeRecord[]
  oversizedFunctions: FunctionSpan[]
  topFiles: FileSizeRecord[]
  topFunctions: FunctionSpan[]
  durationMs: number
}

export const DEFAULT_MAX_FILE_LINES = 2000
export const DEFAULT_MAX_FN_LINES = 150
export const DEFAULT_TOP_N = 15

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
      functions.push({
        file: fileLabel,
        name: resolveFunctionName(node),
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

/** Run the warn-only (or `--strict`) function-length and file-growth ratchet over a directory. */
export function runFunctionGrowthCheck(options: FunctionGrowthOptions = {}): FunctionGrowthReport {
  const t0 = Date.now()
  const rootDir = resolve(options.rootDir ?? join(fileURLToPath(import.meta.url), '../..'))
  const targetDir = resolve(rootDir, options.dir ?? 'src/server')
  const maxFileLines = options.maxFileLines ?? DEFAULT_MAX_FILE_LINES
  const maxFnLines = options.maxFnLines ?? DEFAULT_MAX_FN_LINES
  const top = Math.max(1, options.top ?? DEFAULT_TOP_N)
  const strict = Boolean(options.strict)

  const files = collectTsFiles(targetDir)
  const fileRecords: FileSizeRecord[] = []
  const allFunctions: FunctionSpan[] = []

  for (const absPath of files) {
    if (!statSync(absPath).isFile()) continue
    const rel = relative(rootDir, absPath).replace(/\\/g, '/')
    const source = readFileSync(absPath, 'utf8')
    const { lines, functions } = analyzeSource(source, rel)
    fileRecords.push({ file: rel, lines })
    for (const fn of functions) allFunctions.push(fn)
  }

  fileRecords.sort((a, b) => b.lines - a.lines || a.file.localeCompare(b.file))
  allFunctions.sort((a, b) => b.lines - a.lines || a.file.localeCompare(b.file) || a.startLine - b.startLine)

  const oversizedFiles = fileRecords.filter(f => f.lines > maxFileLines)
  const oversizedFunctions = allFunctions.filter(fn => fn.lines > maxFnLines)
  const ok = strict ? oversizedFiles.length === 0 && oversizedFunctions.length === 0 : true

  return {
    ok,
    strict,
    dir: relative(rootDir, targetDir).replace(/\\/g, '/') || '.',
    filesScanned: fileRecords.length,
    functionsScanned: allFunctions.length,
    maxFileLines,
    maxFnLines,
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
