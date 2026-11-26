#!/usr/bin/env node
/**
 * R2-12 Direct DB Writes Ratchet (`scripts/check-direct-db-writes.ts`).
 *
 * Enforces repository authority over persistence mutations in `src/server/**`:
 *  1. ZERO-TOLERANCE GATE: Zero direct writes to `findings` (either Drizzle
 *     `.db.insert/update/delete(findings)` or raw SQL `INSERT/UPDATE/DELETE` targeting
 *     `findings`) anywhere outside `store.ts`, `store-*.ts`, and `finding-codec.ts`.
 *  2. MONOTONE BASELINE RATCHET: All other direct Drizzle `.db.(insert|update|delete)(...)`
 *     writes outside `store.ts` and `store-*.ts` must stay at or below the per-file baseline
 *     (and no unlisted file may introduce direct `.db` writes).
 *
 * Usage:
 *   node scripts/check-direct-db-writes.ts
 *   node scripts/check-direct-db-writes.ts --json
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join, posix, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import ts from 'typescript'

const EXCLUDED_DIRS = new Set(['node_modules', '.git', 'dist', '.output', '.nitro', '.vinxi', '.tanstack', 'coverage'])
const STORE_OWNED_FILE_RE = /^src\/server\/(?:store|store-[a-z-]+|finding-codec)\.ts$/
const TEST_FILE_RE = /(?:\.test|\.spec)\.[^./\\]+$/i

/**
 * Per-file monotone baseline of remaining non-`findings` Drizzle `.db.(insert|update|delete)` writes
 * outside `store.ts` / `store-*.ts`. Counts may only go DOWN over time.
 */
export const BASELINE_DIRECT_DB_WRITES: Readonly<Record<string, number>> = Object.freeze({
  'src/server/browser-session-auth.ts': 1,
  'src/server/canary-broker.ts': 3,
  'src/server/model-settings.ts': 7,
  'src/server/oob-drain.ts': 1,
  'src/server/patch-workflow.ts': 1,
  'src/server/persona-vault.ts': 3,
  'src/server/run-actor.ts': 3,
})

const RAW_SQL_FINDINGS_WRITE_RE = /\b(?:INSERT\s+(?:OR\s+\w+\s+)?INTO|UPDATE(?:\s+OR\s+\w+)?|DELETE\s+FROM)\s+[`"']?findings[`"']?\b/i

export interface DirectDbWriteHit {
  file: string
  line: number
  kind: 'drizzle_findings_write' | 'raw_sql_findings_write' | 'drizzle_direct_write'
  method: string
  target: string
}

export interface DirectDbWriteAuditResult {
  ok: boolean
  rootDir: string
  filesScanned: number
  findingsWriteHits: DirectDbWriteHit[]
  directDbWriteHits: DirectDbWriteHit[]
  countsByFile: Record<string, number>
  regressions: string[]
  totalDirectWrites: number
  baselineTotal: number
}

function toPosix(p: string): string {
  return sep === '/' ? p : p.split(sep).join(posix.sep)
}

function collectServerTsFiles(rootDir: string): string[] {
  const serverDir = join(rootDir, 'src', 'server')
  if (!existsSync(serverDir)) return []
  const out: string[] = []
  const walk = (dir: string) => {
    const entries = readdirSync(dir, { withFileTypes: true })
    entries.sort((a, b) => a.name.localeCompare(b.name))
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        if (EXCLUDED_DIRS.has(entry.name)) continue
        walk(full)
      } else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
        const rel = toPosix(relative(rootDir, full))
        if (!TEST_FILE_RE.test(rel)) out.push(rel)
      }
    }
  }
  walk(serverDir)
  return out
}

function extractTargetTableName(arg: ts.Expression | undefined, sf: ts.SourceFile): string {
  if (!arg) return '<unknown>'
  if (ts.isIdentifier(arg)) return arg.text
  if (ts.isPropertyAccessExpression(arg)) return arg.name.text
  return arg.getText(sf).trim()
}

function isDbPropertyAccess(expr: ts.Expression): boolean {
  if (ts.isPropertyAccessExpression(expr)) {
    return expr.name.text === 'db'
  }
  if (ts.isNonNullExpression(expr)) {
    return isDbPropertyAccess(expr.expression)
  }
  return false
}

export function scanDirectDbWrites(rootDir: string): DirectDbWriteAuditResult {
  const files = collectServerTsFiles(rootDir)
  const findingsWriteHits: DirectDbWriteHit[] = []
  const directDbWriteHits: DirectDbWriteHit[] = []
  const countsByFile: Record<string, number> = {}

  for (const rel of files) {
    if (STORE_OWNED_FILE_RE.test(rel)) continue
    const abs = join(rootDir, rel)
    if (!statSync(abs).isFile()) continue
    const sourceText = readFileSync(abs, 'utf8')
    const sf = ts.createSourceFile(abs, sourceText, ts.ScriptTarget.Latest, true)

    const visit = (node: ts.Node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const methodName = node.expression.name.text
        const receiver = node.expression.expression

        // 1. Drizzle `.db.(insert|update|delete)(table)`
        if ((methodName === 'insert' || methodName === 'update' || methodName === 'delete') && isDbPropertyAccess(receiver)) {
          const target = extractTargetTableName(node.arguments[0], sf)
          const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
          if (target === 'findings') {
            findingsWriteHits.push({
              file: rel,
              line,
              kind: 'drizzle_findings_write',
              method: `db.${methodName}`,
              target,
            })
          } else {
            directDbWriteHits.push({
              file: rel,
              line,
              kind: 'drizzle_direct_write',
              method: `db.${methodName}`,
              target,
            })
            countsByFile[rel] = (countsByFile[rel] ?? 0) + 1
          }
        }

        // 2. Raw SQL `.prepare(...)` / `.exec(...)` targeting `findings`
        if (methodName === 'prepare' || methodName === 'exec') {
          const firstArg = node.arguments[0]
          if (firstArg && (ts.isStringLiteral(firstArg) || ts.isNoSubstitutionTemplateLiteral(firstArg) || ts.isTemplateExpression(firstArg))) {
            const sqlText = firstArg.getText(sf)
            if (RAW_SQL_FINDINGS_WRITE_RE.test(sqlText)) {
              const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
              findingsWriteHits.push({
                file: rel,
                line,
                kind: 'raw_sql_findings_write',
                method: methodName,
                target: 'findings',
              })
            }
          }
        }
      }
      ts.forEachChild(node, visit)
    }
    visit(sf)
  }

  const regressions: string[] = []
  for (const hit of findingsWriteHits) {
    regressions.push(
      `Direct findings-table write forbidden outside store-*.ts: ${hit.file}:${hit.line} (${hit.method}(${hit.target}))`,
    )
  }

  for (const [file, count] of Object.entries(countsByFile).sort(([a], [b]) => a.localeCompare(b))) {
    const allowed = BASELINE_DIRECT_DB_WRITES[file] ?? 0
    if (count > allowed) {
      regressions.push(
        `Direct .db write count regression in ${file}: got ${count}, baseline max ${allowed}`,
      )
    }
  }

  const baselineTotal = Object.values(BASELINE_DIRECT_DB_WRITES).reduce((acc, n) => acc + n, 0)
  return {
    ok: regressions.length === 0,
    rootDir,
    filesScanned: files.length,
    findingsWriteHits,
    directDbWriteHits,
    countsByFile,
    regressions,
    totalDirectWrites: directDbWriteHits.length,
    baselineTotal,
  }
}

function main() {
  const args = process.argv.slice(2)
  const jsonMode = args.includes('--json')
  const rootDir = resolve(fileURLToPath(new URL('..', import.meta.url)))
  const result = scanDirectDbWrites(rootDir)
  if (jsonMode) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
  } else if (result.ok) {
    process.stdout.write(
      `PASS: direct DB writes ratchet (${result.findingsWriteHits.length} direct findings writes, `
      + `${result.totalDirectWrites}/${result.baselineTotal} legacy non-findings .db writes across `
      + `${result.filesScanned} server files)\n`,
    )
  } else {
    process.stderr.write(`FAIL: direct DB writes ratchet (${result.regressions.length} violation(s)):\n`)
    for (const r of result.regressions) {
      process.stderr.write(`  - ${r}\n`)
    }
  }
  process.exit(result.ok ? 0 : 1)
}

const isEntrypoint = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (isEntrypoint) {
  main()
}
