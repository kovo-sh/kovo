#!/usr/bin/env node
/**
 * Exhaustive Union Switch Lint (`R3-18`, plans/claude_quality_3.md §18).
 *
 * Fast (<2s), parser-only TypeScript AST linter over `src/**\/*.{ts,tsx}` that enforces
 * consumer closure for core discriminated string unions:
 *   - `ChainStepStatus` (derived dynamically from `STEP_STATUS` in `src/step-status.ts`)
 *   - `RunStatus` (`src/domain.ts`)
 *   - `WorkerStatus` (`src/domain.ts`)
 *   - `FindingStatus` (`src/domain.ts`)
 *   - `ReplayVerdict` & `RetestVerdict` (`src/server/replay-verifier.ts`)
 *   - `DynamicRetestVerdict` (`src/domain.ts`)
 *   - `FindingDisposition` (`src/findings-view.ts`)
 *   - `RunStatusCategory` (`src/server/run-status.ts`)
 *
 * Any `switch` statement whose string-literal `case` clauses target one of these guarded
 * unions must:
 *   1. Handle every member of the union (no silently dropped cases when a new status/verdict
 *      is added), AND
 *   2. Include a `default:` clause that asserts exhaustiveness via `assertNever(...)` or a
 *      `never` assignment (`const _exhaustive: never = ...`).
 *
 * Opt-out for intentional partial switches (e.g., narrow UI filters) requires an explicit
 * inline justification comment on the `switch` line or immediately preceding line:
 *   `// check-exhaustive: allow-partial <reason>`
 *
 * Usage:
 *   node scripts/check-exhaustive.ts
 *   node scripts/check-exhaustive.ts --json
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import ts from 'typescript'

export interface GuardedUnionSpec {
  readonly name: string
  readonly sourceFile: string
  readonly members: readonly string[]
}

export interface ExhaustiveViolation {
  readonly file: string
  readonly line: number
  readonly unionName: string
  readonly expression: string
  readonly cases: readonly string[]
  readonly missingMembers: readonly string[]
  readonly hasDefault: boolean
  readonly hasAssertNever: boolean
  readonly reason: string
}

export interface ExhaustiveReport {
  readonly ok: boolean
  readonly rootDir: string
  readonly filesScanned: number
  readonly switchesChecked: number
  readonly guardedUnions: readonly { name: string; count: number }[]
  readonly violations: readonly ExhaustiveViolation[]
  readonly durationMs: number
}

export interface ExhaustiveCheckOptions {
  rootDir?: string
  scanDirs?: readonly string[]
  unions?: readonly GuardedUnionSpec[]
}

const ALLOW_PARTIAL_RE = /check-exhaustive:\s*allow-partial\b/i
const ASSERT_NEVER_RE = /\bassertNever\s*\(|:\s*never\b/

function parseStringUnionFromFile(absPath: string, typeName: string): string[] {
  const sourceText = readFileSync(absPath, 'utf8')
  const sf = ts.createSourceFile(absPath, sourceText, ts.ScriptTarget.Latest, true)
  const members: string[] = []

  function collectUnion(typeNode: ts.TypeNode): void {
    if (ts.isUnionTypeNode(typeNode)) {
      for (const member of typeNode.types) {
        if (ts.isLiteralTypeNode(member) && ts.isStringLiteral(member.literal)) {
          members.push(member.literal.text)
        }
      }
    }
  }

  function visit(node: ts.Node): void {
    if (ts.isTypeAliasDeclaration(node) && node.name.text === typeName) {
      collectUnion(node.type)
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return members
}

function parseConstArrayUnionFromFile(absPath: string, constName: string): string[] {
  const sourceText = readFileSync(absPath, 'utf8')
  const sf = ts.createSourceFile(absPath, sourceText, ts.ScriptTarget.Latest, true)
  const members: string[] = []

  function visit(node: ts.Node): void {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === constName && node.initializer) {
      let expr: ts.Expression = node.initializer
      while (ts.isAsExpression(expr) || ts.isSatisfiesExpression(expr) || ts.isParenthesizedExpression(expr)) {
        expr = expr.expression
      }
      if (ts.isArrayLiteralExpression(expr)) {
        for (const el of expr.elements) {
          if (ts.isStringLiteral(el)) members.push(el.text)
        }
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return members
}

function parseStepStatusKeysFromFile(absPath: string): string[] {
  const sourceText = readFileSync(absPath, 'utf8')
  const sf = ts.createSourceFile(absPath, sourceText, ts.ScriptTarget.Latest, true)
  const keys: string[] = []

  function visit(node: ts.Node): void {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'STEP_STATUS' && node.initializer) {
      let expr: ts.Expression = node.initializer
      while (ts.isAsExpression(expr) || ts.isSatisfiesExpression(expr) || ts.isParenthesizedExpression(expr)) {
        expr = expr.expression
      }
      if (ts.isObjectLiteralExpression(expr)) {
        for (const prop of expr.properties) {
          if (ts.isPropertyAssignment(prop)) {
            if (ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name)) {
              keys.push(prop.name.text)
            }
          }
        }
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return keys
}

export function loadDefaultGuardedUnions(rootDir: string): GuardedUnionSpec[] {
  const stepStatusPath = join(rootDir, 'src', 'step-status.ts')
  const domainPath = join(rootDir, 'src', 'domain.ts')
  const replayVerifierPath = join(rootDir, 'src', 'server', 'replay-verifier.ts')
  const findingsViewPath = join(rootDir, 'src', 'findings-view.ts')
  const runStatusPath = join(rootDir, 'src', 'server', 'run-status.ts')

  const specs: GuardedUnionSpec[] = []
  const add = (name: string, relPath: string, members: string[]) => {
    if (members.length >= 2) {
      specs.push({ name, sourceFile: relPath, members })
    }
  }

  if (existsSync(stepStatusPath)) {
    add('ChainStepStatus', 'src/step-status.ts', parseStepStatusKeysFromFile(stepStatusPath))
  }
  if (existsSync(domainPath)) {
    add('RunStatus', 'src/domain.ts', parseStringUnionFromFile(domainPath, 'RunStatus'))
    add('WorkerStatus', 'src/domain.ts', parseStringUnionFromFile(domainPath, 'WorkerStatus'))
    add('FindingStatus', 'src/domain.ts', parseConstArrayUnionFromFile(domainPath, 'findingStatuses'))
    add('DynamicRetestVerdict', 'src/domain.ts', parseConstArrayUnionFromFile(domainPath, 'dynamicRetestVerdicts'))
  }
  if (existsSync(replayVerifierPath)) {
    add('ReplayVerdict', 'src/server/replay-verifier.ts', parseStringUnionFromFile(replayVerifierPath, 'ReplayVerdict'))
    add('RetestVerdict', 'src/server/replay-verifier.ts', parseStringUnionFromFile(replayVerifierPath, 'RetestVerdict'))
  }
  if (existsSync(findingsViewPath)) {
    add('FindingDisposition', 'src/findings-view.ts', parseStringUnionFromFile(findingsViewPath, 'FindingDisposition'))
  }
  if (existsSync(runStatusPath)) {
    add('RunStatusCategory', 'src/server/run-status.ts', parseStringUnionFromFile(runStatusPath, 'RunStatusCategory'))
  }

  return specs
}

function listSourceFiles(dir: string): string[] {
  if (!existsSync(dir)) return []
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      out.push(...listSourceFiles(full))
    } else if (
      (entry.name.endsWith('.ts') || entry.name.endsWith('.tsx'))
      && !entry.name.endsWith('.d.ts')
    ) {
      out.push(full)
    }
  }
  return out.sort()
}

function hasPartialAllowComment(sourceText: string, switchLine: number): boolean {
  const lines = sourceText.split(/\r?\n/)
  const idx = switchLine - 1
  for (let i = Math.max(0, idx - 2); i <= Math.min(lines.length - 1, idx); i += 1) {
    if (ALLOW_PARTIAL_RE.test(lines[i] ?? '')) return true
  }
  return false
}

/**
 * Determine which guarded union (if any) a switch statement targets.
 * Matches when:
 *  - Every string-literal `case` belongs to the union,
 *  - At least 2 distinct union members are switched on (or >= 3 when unions overlap like `running`/`complete`),
 *  - When multiple unions match (e.g. `complete`/`failed` overlap between `RunStatus` and `WorkerStatus`),
 *    select the most specific union (smallest superset that uniquely matches distinctive members or expression hint).
 */
function matchGuardedUnion(
  exprText: string,
  cases: readonly string[],
  unions: readonly { spec: GuardedUnionSpec; set: ReadonlySet<string> }[],
): GuardedUnionSpec | null {
  if (cases.length < 2) return null
  const uniqueCases = [...new Set(cases)]
  if (uniqueCases.length < 2) return null

  const candidates = unions.filter(u => uniqueCases.every(c => u.set.has(c)))
  if (candidates.length === 0) return null
  if (candidates.length === 1) return candidates[0]!.spec

  // Tie-break overlapping unions using exact case-set equality first, then expression naming hints.
  const exact = candidates.find(c => c.set.size === uniqueCases.length)
  if (exact) return exact.spec

  const lowerExpr = exprText.toLowerCase()
  const hintOrder: Array<{ re: RegExp; name: string }> = [
    { re: /step|chain/, name: 'ChainStepStatus' },
    { re: /worker|assign/, name: 'WorkerStatus' },
    { re: /run|lifecycle/, name: 'RunStatus' },
    { re: /category/, name: 'RunStatusCategory' },
    { re: /disposition/, name: 'FindingDisposition' },
    { re: /retest/, name: 'RetestVerdict' },
    { re: /verdict/, name: 'ReplayVerdict' },
    { re: /finding/, name: 'FindingStatus' },
  ]
  for (const { re, name } of hintOrder) {
    if (re.test(lowerExpr)) {
      const hit = candidates.find(c => c.spec.name === name)
      if (hit) return hit.spec
    }
  }

  // Prefer the union with the highest overlap ratio (smallest union containing all cases).
  candidates.sort((a, b) => a.set.size - b.set.size)
  return candidates[0]!.spec
}

export function checkExhaustiveSource(
  relPath: string,
  sourceText: string,
  unions: readonly GuardedUnionSpec[],
): { switchesChecked: number; violations: ExhaustiveViolation[] } {
  const sf = ts.createSourceFile(relPath, sourceText, ts.ScriptTarget.Latest, true)
  const preparedUnions = unions.map(spec => ({ spec, set: new Set<string>(spec.members) }))
  const violations: ExhaustiveViolation[] = []
  let switchesChecked = 0

  function visit(node: ts.Node): void {
    if (ts.isSwitchStatement(node)) {
      const cases: string[] = []
      let hasNonStringCase = false
      let hasDefault = false
      let defaultText = ''

      for (const clause of node.caseBlock.clauses) {
        if (ts.isDefaultClause(clause)) {
          hasDefault = true
          defaultText = clause.getText(sf)
        } else if (ts.isStringLiteral(clause.expression)) {
          cases.push(clause.expression.text)
        } else {
          hasNonStringCase = true
        }
      }

      if (!hasNonStringCase && cases.length >= 2) {
        const exprText = node.expression.getText(sf)
        const matched = matchGuardedUnion(exprText, cases, preparedUnions)
        if (matched) {
          switchesChecked += 1
          const switchLine = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
          if (!hasPartialAllowComment(sourceText, switchLine)) {
            const caseSet = new Set(cases)
            const missingMembers = matched.members.filter(m => !caseSet.has(m))
            const hasAssertNever = hasDefault && ASSERT_NEVER_RE.test(defaultText)
            if (missingMembers.length > 0 || !hasAssertNever) {
              const reasons: string[] = []
              if (missingMembers.length > 0) {
                reasons.push(`missing ${matched.name} case(s): ${missingMembers.join(', ')}`)
              }
              if (!hasDefault) {
                reasons.push('missing default clause with assertNever(...)')
              } else if (!hasAssertNever) {
                reasons.push('default clause does not enforce exhaustiveness via assertNever(...) or `: never`')
              }
              violations.push({
                file: relPath,
                line: switchLine,
                unionName: matched.name,
                expression: exprText,
                cases,
                missingMembers,
                hasDefault,
                hasAssertNever,
                reason: reasons.join('; '),
              })
            }
          }
        }
      }
    }
    ts.forEachChild(node, visit)
  }

  visit(sf)
  return { switchesChecked, violations }
}

export function runExhaustiveCheck(options: ExhaustiveCheckOptions = {}): ExhaustiveReport {
  const started = Date.now()
  const rootDir = resolve(options.rootDir ?? join(fileURLToPath(new URL('..', import.meta.url))))
  const unions = options.unions ?? loadDefaultGuardedUnions(rootDir)
  const scanDirs = options.scanDirs ?? ['src']
  const files = scanDirs.flatMap(dir => listSourceFiles(join(rootDir, dir)))

  let switchesChecked = 0
  const violations: ExhaustiveViolation[] = []

  for (const absPath of files) {
    const relPath = relative(rootDir, absPath).replace(/\\/g, '/')
    const sourceText = readFileSync(absPath, 'utf8')
    const res = checkExhaustiveSource(relPath, sourceText, unions)
    switchesChecked += res.switchesChecked
    violations.push(...res.violations)
  }

  return {
    ok: violations.length === 0,
    rootDir,
    filesScanned: files.length,
    switchesChecked,
    guardedUnions: unions.map(u => ({ name: u.name, count: u.members.length })),
    violations,
    durationMs: Date.now() - started,
  }
}

function main(): void {
  const asJson = process.argv.includes('--json')
  const report = runExhaustiveCheck()
  if (asJson) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
  } else {
    const unionSummary = report.guardedUnions.map(u => `${u.name}(${u.count})`).join(', ')
    if (report.ok) {
      process.stdout.write(
        `check-exhaustive PASS (${report.durationMs}ms): scanned ${report.filesScanned} files, checked ${report.switchesChecked} switches across [${unionSummary}], violations=0\n`,
      )
    } else {
      process.stderr.write(
        `check-exhaustive FAIL (${report.durationMs}ms): ${report.violations.length} violation(s) across ${report.filesScanned} files:\n`,
      )
      for (const v of report.violations) {
        process.stderr.write(`  - ${v.file}:${v.line} switch (${v.expression}) [${v.unionName}]: ${v.reason}\n`)
      }
    }
  }
  process.exit(report.ok ? 0 : 1)
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main()
}
