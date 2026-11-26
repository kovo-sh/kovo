#!/usr/bin/env node
/**
 * AST Empty-Catch Ratchet Lint for Lifecycle & Orchestration Files (`R3-07`).
 *
 * Fast (<1s), parser-only (`ts.createSourceFile`, no typechecker) scanner over:
 *   - `src/server/execution.ts`
 *   - `src/server/run-actor.ts`
 *   - `src/server/exec-*.ts`
 *   - `src/server/assignment-claim.ts`
 *   - `src/server/run-disposers.ts`
 *
 * Flags every TypeScript `CatchClause` whose block has zero statements (`catch {}`,
 * `catch { /* comment *\/ }`, `catch (e) {}`), which silently swallows lifecycle
 * settlement/requeue/eviction failures instead of routing through `settleOrReport(...)`.
 *
 * Strictly monotone (removal-only) baseline:
 *   - Fails (exit 1) if ANY watched file exceeds its per-file baseline count.
 *   - Fails (exit 1) if ANY newly added watched file introduces an empty catch (`0` allowed).
 *   - Fails (exit 1) if `src/server/assignment-claim.ts` or `src/server/run-disposers.ts` has >0.
 *   - Exits 0 at or below baseline, printing retired counts so the baseline can tighten downward.
 *
 * Usage:
 *   node scripts/check-empty-catch.ts [--root <dir>] [--json] [--help]
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, posix, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import ts from 'typescript'

/** Total empty catches across watched lifecycle files before R3-07 (`3a552f1` / pre-R3-07 HEAD). */
export const PRE_R3_07_EMPTY_CATCH_TOTAL = 188

/**
 * Strictly non-increasing per-file baseline of legacy empty `catch {}` blocks.
 * Counts may ONLY go down as remaining legacy blocks migrate to `settleOrReport(...)`.
 * New settlement/claim modules (`assignment-claim.ts`, `run-disposers.ts`) are pinned at 0.
 */
export const BASELINE_EMPTY_CATCH_BY_FILE: Readonly<Record<string, number>> = Object.freeze({
  'src/server/assignment-claim.ts': 0,
  'src/server/exec-board.ts': 11,
  'src/server/exec-brokered-transport.ts': 2,
  'src/server/exec-dispatch.ts': 10,
  'src/server/exec-exchange.ts': 0,
  'src/server/exec-floor-lane.ts': 10,
  'src/server/exec-recon-planner.ts': 48,
  'src/server/exec-verify.ts': 9,
  'src/server/exec-worker-runner.ts': 2,
  'src/server/execution.ts': 63,
  'src/server/run-actor.ts': 23,
  'src/server/run-disposers.ts': 0,
})

export const BASELINE_EMPTY_CATCH_TOTAL = Object.values(BASELINE_EMPTY_CATCH_BY_FILE).reduce((sum, n) => sum + n, 0)

export interface EmptyCatchHit {
  file: string
  line: number
  excerpt: string
}

export interface EmptyCatchAuditOptions {
  rootDir?: string
  baselineByFile?: Readonly<Record<string, number>>
}

export interface EmptyCatchAuditResult {
  ok: boolean
  rootDir: string
  filesScanned: number
  totalEmptyCatches: number
  baselineTotal: number
  preR307Total: number
  countsByFile: Record<string, number>
  hits: EmptyCatchHit[]
  regressions: string[]
  retiredByFile: Record<string, number>
  durationMs: number
}

const WATCHED_LIFECYCLE_FILE_RE = /^(?:execution|run-actor|assignment-claim|run-disposers|exec-[a-z0-9-]+)\.ts$/i

function toPosix(p: string): string {
  return sep === '/' ? p : p.split(sep).join(posix.sep)
}

function collectWatchedLifecycleFiles(rootDir: string): string[] {
  const serverDir = join(rootDir, 'src', 'server')
  if (!existsSync(serverDir)) return []
  return readdirSync(serverDir, { withFileTypes: true })
    .filter(entry => entry.isFile() && WATCHED_LIFECYCLE_FILE_RE.test(entry.name) && !entry.name.endsWith('.d.ts'))
    .map(entry => toPosix(relative(rootDir, join(serverDir, entry.name))))
    .sort()
}

function scanFileForEmptyCatches(source: string, relFile: string): EmptyCatchHit[] {
  const sf = ts.createSourceFile(relFile, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const lines = source.split(/\r?\n/)
  const hits: EmptyCatchHit[] = []

  const visit = (node: ts.Node): void => {
    if (ts.isCatchClause(node) && node.block.statements.length === 0) {
      const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
      hits.push({
        file: relFile,
        line,
        excerpt: (lines[line - 1] ?? '').trim().slice(0, 140),
      })
    }
    ts.forEachChild(node, visit)
  }

  visit(sf)
  return hits
}

export function runEmptyCatchCheck(options: EmptyCatchAuditOptions = {}): EmptyCatchAuditResult {
  const t0 = Date.now()
  const rootDir = resolve(options.rootDir ?? join(fileURLToPath(import.meta.url), '../..'))
  const baselineByFile = options.baselineByFile ?? BASELINE_EMPTY_CATCH_BY_FILE
  const baselineTotal = Object.values(baselineByFile).reduce((sum, n) => sum + n, 0)

  const files = collectWatchedLifecycleFiles(rootDir)
  const countsByFile: Record<string, number> = {}
  const hits: EmptyCatchHit[] = []
  const regressions: string[] = []
  const retiredByFile: Record<string, number> = {}
  let totalEmptyCatches = 0

  for (const relFile of files) {
    const source = readFileSync(join(rootDir, relFile), 'utf8')
    const fileHits = scanFileForEmptyCatches(source, relFile)
    countsByFile[relFile] = fileHits.length
    totalEmptyCatches += fileHits.length
    for (const h of fileHits) hits.push(h)

    const allowed = baselineByFile[relFile] ?? 0
    if (fileHits.length > allowed) {
      const sampleLines = fileHits.slice(0, 6).map(h => `L${h.line}`).join(', ')
      regressions.push(
        `${relFile}: ${fileHits.length} empty catch(es) exceeds monotone baseline ${allowed} (sample: ${sampleLines})`,
      )
    } else if (fileHits.length < allowed) {
      retiredByFile[relFile] = allowed - fileHits.length
    }
  }

  return {
    ok: regressions.length === 0 && totalEmptyCatches <= baselineTotal,
    rootDir,
    filesScanned: files.length,
    totalEmptyCatches,
    baselineTotal,
    preR307Total: PRE_R3_07_EMPTY_CATCH_TOTAL,
    countsByFile,
    hits,
    regressions,
    retiredByFile,
    durationMs: Date.now() - t0,
  }
}

export interface ClaimDisciplineViolation {
  file: string
  line: number
  kind: 'raw_running_write' | 'hardcoded_lease_literal'
  excerpt: string
}

export interface ClaimDisciplineResult {
  ok: boolean
  filesScanned: number
  violations: ClaimDisciplineViolation[]
}

/**
 * AST guard (`R3-07`): verifies that migrated claim-owner files (`execution.ts`, `store-runs.ts`)
 * never write assignment `status: 'running'` directly via `updateWorker(...)` outside
 * `claimAssignment()` and never hard-code 10/15-minute `leaseExpiresAt` literals outside
 * `run-safety-budgets.ts`.
 */
export function runClaimDisciplineCheck(
  rootDir = resolve(join(fileURLToPath(import.meta.url), '../..')),
  files: readonly string[] = ['src/server/execution.ts', 'src/server/store-runs.ts'],
): ClaimDisciplineResult {
  const violations: ClaimDisciplineViolation[] = []
  for (const rel of files) {
    const abs = join(rootDir, rel)
    if (!existsSync(abs)) continue
    const source = readFileSync(abs, 'utf8')
    const lines = source.split(/\r?\n/)
    const sf = ts.createSourceFile(rel, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'updateWorker') {
        const arg = node.arguments[1]
        if (arg && ts.isObjectLiteralExpression(arg)) {
          for (const prop of arg.properties) {
            if (!ts.isPropertyAssignment(prop)) continue
            const propName = ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name) ? prop.name.text : ''
            if (propName === 'status' && ts.isStringLiteral(prop.initializer) && prop.initializer.text === 'running') {
              const line = sf.getLineAndCharacterOfPosition(prop.getStart(sf)).line + 1
              violations.push({ file: rel, line, kind: 'raw_running_write', excerpt: (lines[line - 1] ?? '').trim().slice(0, 140) })
            }
          }
        }
      } else if (ts.isPropertyAssignment(node)) {
        const propName = ts.isIdentifier(node.name) || ts.isStringLiteral(node.name) ? node.name.text : ''
        if (propName === 'leaseExpiresAt' && /\b(?:10|15)\s*\*\s*60_?000\b/.test(node.initializer.getText(sf))) {
          const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
          violations.push({ file: rel, line, kind: 'hardcoded_lease_literal', excerpt: (lines[line - 1] ?? '').trim().slice(0, 140) })
        }
      }
      ts.forEachChild(node, visit)
    }
    visit(sf)
  }
  return { ok: violations.length === 0, filesScanned: files.length, violations }
}

function parseArgs(argv: string[]): { rootDir?: string; json: boolean; help: boolean } {
  const out: { rootDir?: string; json: boolean; help: boolean } = { json: false, help: false }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--json') out.json = true
    else if (arg === '--help' || arg === '-h') out.help = true
    else if (arg === '--root' && argv[i + 1]) out.rootDir = argv[++i]!
  }
  return out
}

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
if (isMain) {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) {
    console.log('Usage: node scripts/check-empty-catch.ts [--root <dir>] [--json]')
    process.exit(0)
  }
  const result = runEmptyCatchCheck({ ...(args.rootDir ? { rootDir: args.rootDir } : {}) })
  if (args.json) {
    console.log(JSON.stringify(result, null, 2))
  } else {
    const retiredTotal = Object.values(result.retiredByFile).reduce((sum, n) => sum + n, 0)
    const status = result.ok ? 'PASS' : 'FAIL'
    console.log(
      `check-empty-catch ${status} (${result.durationMs}ms): scanned ${result.filesScanned} lifecycle files — ` +
      `total=${result.totalEmptyCatches}/${result.baselineTotal} (pre-R3-07=${result.preR307Total}, retiredBelowBaseline=${retiredTotal})`,
    )
    if (result.regressions.length > 0) {
      for (const r of result.regressions) console.error(`  FAIL  ${r}`)
    }
  }
  process.exit(result.ok ? 0 : 1)
}
