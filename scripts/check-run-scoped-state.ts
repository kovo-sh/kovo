#!/usr/bin/env node
/**
 * Per-Run Module-Scoped State Ratchet Lint (R2-08, plans/claude_quality_2.md §8).
 *
 * Uses the TypeScript compiler AST (`ts.createSourceFile`) to scan `src/server/**\/*.ts`
 * (excluding test files and `src/server/run-disposers.ts`) for top-level mutable
 * `new Map()` / `new Set()` declarations whose identifier or type annotation is keyed by
 * `run` / `assignment` / `persona` and is NOT registered with `registerRunDisposer(...)`.
 *
 * Strictly non-increasing ratchet:
 *   - Fails (exit 1) if any NEW un-registered per-run Map/Set appears outside the baseline set.
 *   - Fails (exit 1) if the total un-registered count exceeds `BASELINE_MAX_UNREGISTERED`.
 *   - Exits 0 at or below baseline (reporting any retired baseline entries so the ratchet can
 *     be tightened downward as remaining legacy maps migrate onto `registerRunDisposer`).
 *
 * Usage:
 *   node scripts/check-run-scoped-state.ts [--root <dir>] [--json] [--help]
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, posix, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import ts from 'typescript'

export interface RunScopedStateFinding {
  /** Stable identifier `<file>::<name>` (or `<file>::<Class>.<field>` for class fields). */
  key: string
  /** Repo-relative POSIX path. */
  file: string
  /** 1-based line number. */
  line: number
  /** Variable or `<Class>.<field>` name. */
  name: string
  /** Collection constructor kind. */
  kind: 'Map' | 'Set'
  /** Declaration scope: top-level module variable or class instance field. */
  scope?: 'module' | 'class-field'
  /** Whether the variable/field is registered with `registerRunDisposer(...)` or disposed in-class. */
  registered: boolean
  /** Trimmed source line excerpt. */
  excerpt: string
}

export interface RunScopedStateScanOptions {
  /** Relative directory under rootDir to scan (default: `src/server`). */
  dir?: string
  /** Override baseline allowed keys (default: `BASELINED_UNREGISTERED_RUN_SCOPED_STATE`). */
  baselinedKeys?: readonly string[]
  /** Override baseline max count (default: `BASELINE_MAX_UNREGISTERED`). */
  baselineMax?: number
}

export interface RunScopedStateScanResult {
  ok: boolean
  rootDir: string
  filesScanned: number
  registeredCount: number
  unregisteredCount: number
  baselineMax: number
  registered: RunScopedStateFinding[]
  unregistered: RunScopedStateFinding[]
  newViolations: RunScopedStateFinding[]
  retiredBaselineKeys: string[]
  durationMs: number
}

/**
 * Exact pre-existing un-registered per-run module-level Maps/Sets on `main` at R2-08 landing.
 * Strictly non-increasing: entries may only be REMOVED as they migrate onto `registerRunDisposer`.
 */
export const BASELINED_UNREGISTERED_RUN_SCOPED_STATE: readonly string[] = [
  'src/server/active-clock.ts::assignmentClocks',
  'src/server/active-clock.ts::runClocks',
  'src/server/canary-broker.ts::observedSecondOrderByRun',
  'src/server/derived-custody.ts::runCustodyBudgets',
  'src/server/exec-verify.ts::ExecVerifier.fallbackVaults',
  'src/server/oob-drain.ts::activeFinalizingRuns',
  'src/server/patch-workflow.ts::gate6RunLocks',
  'src/server/probe-plan.ts::ProbePlanRegistry.plans',
  'src/server/verify-support.ts::runBrowserRegistry',
] as const

export const BASELINE_MAX_UNREGISTERED = BASELINED_UNREGISTERED_RUN_SCOPED_STATE.length

const EXCLUDED_DIRS = new Set(['node_modules', '.git', 'tests', '__tests__', 'benchmarks'])
const EXCLUDED_FILE_RE = /(?:\.test|\.spec)\.[^./\\]+$/i
const EXEMPT_FILES = new Set(['src/server/run-disposers.ts'])

/**
 * Word-aware camelCase/snake_case matcher for `run` / `assignment` / `persona` identifiers.
 * Deliberately excludes unrelated words like `runtime` (where `run` is followed by lowercase `t`).
 */
const RUN_SCOPED_KEY_RE =
  /(?:^|[\s_-])(?:run|runs|assignment|assignments|persona|personas)(?:$|[\s_-]|[A-Z0-9])|(?:Run|Runs|Assignment|Assignments|Persona|Personas)(?:$|[\s_-]|[A-Z0-9])/

function toPosixRelative(rootDir: string, absPath: string): string {
  const rel = relative(rootDir, absPath)
  return sep === '/' ? rel : rel.split(sep).join(posix.sep)
}

function collectServerTsFiles(dirPath: string, out: string[]): void {
  if (!existsSync(dirPath)) return
  const entries = readdirSync(dirPath, { withFileTypes: true })
  entries.sort((a, b) => a.name.localeCompare(b.name))
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue
    const full = join(dirPath, entry.name)
    if (entry.isDirectory()) {
      if (EXCLUDED_DIRS.has(entry.name)) continue
      collectServerTsFiles(full, out)
    } else if (entry.isFile()) {
      if (!entry.name.endsWith('.ts') || entry.name.endsWith('.d.ts')) continue
      if (EXCLUDED_FILE_RE.test(entry.name)) continue
      out.push(full)
    }
  }
}

/** Collect all identifier names referenced inside an AST subtree. */
function collectReferencedIdentifiers(node: ts.Node, out: Set<string>): void {
  if (ts.isIdentifier(node)) {
    out.add(node.text)
    return
  }
  ts.forEachChild(node, child => collectReferencedIdentifiers(child, out))
}

/** Check whether an AST subtree mutates/cleans `varName` via `.delete(...)` or `.clear(...)`. */
function subtreeCleansCollection(node: ts.Node, varName: string): boolean {
  let found = false
  const visit = (n: ts.Node): void => {
    if (found) return
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
      const target = n.expression.expression
      const method = n.expression.name.text
      if (ts.isIdentifier(target) && target.text === varName && (method === 'delete' || method === 'clear')) {
        found = true
        return
      }
    }
    ts.forEachChild(n, visit)
  }
  visit(node)
  return found
}

/** Collect identifier names referenced inside any `registerRunDisposer(...)` call in `sf`. */
function collectDisposerReferencedIdentifiers(sf: ts.SourceFile): Set<string> {
  const refs = new Set<string>()
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'registerRunDisposer') {
      for (const arg of node.arguments) {
        collectReferencedIdentifiers(arg, refs)
      }
      return
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return refs
}

function isRegisteredWithRunDisposer(
  sf: ts.SourceFile,
  disposerRefs: ReadonlySet<string>,
  varName: string,
): boolean {
  if (disposerRefs.size === 0) return false
  if (disposerRefs.has(varName)) return true
  // Check top-level function declarations (or const arrow/function vars) that clean `varName`
  // and are invoked from a `registerRunDisposer(...)` callback.
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name && stmt.body) {
      if (disposerRefs.has(stmt.name.text) && subtreeCleansCollection(stmt.body, varName)) {
        return true
      }
    } else if (ts.isVariableStatement(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        if (ts.isIdentifier(decl.name) && decl.initializer && disposerRefs.has(decl.name.text)) {
          if (
            (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer)) &&
            subtreeCleansCollection(decl.initializer.body, varName)
          ) {
            return true
          }
        }
      }
    }
  }
  return false
}

const CLASS_KEY_ARG_RE =
  /\b(?:runId|run_id|assignmentId|assignment_id|personaId|persona_id)\b|\b(?:run|assignment|persona)\.id\b/i

function isThisPropAccess(expr: ts.Expression, propName: string): boolean {
  return (
    ts.isPropertyAccessExpression(expr)
    && expr.expression.kind === ts.SyntaxKind.ThisKeyword
    && expr.name.text === propName
  )
}

/**
 * Inspect a class body for mutations and disposal of `this.<propName>`:
 *  - `mutatedWithRunKey`: called `.set(arg, ...)` or `.add(arg)` with a run/assignment/persona key arg.
 *  - `mutatedAny`: called `.set(...)` or `.add(...)` with any arg.
 *  - `disposed`: calls `this.<propName>.delete(...)` or `.clear(...)`, or delegates the field reference
 *    as an argument/property value to an external coordinator/cleanup helper.
 */
function analyzeClassFieldLifecycle(
  cls: ts.ClassLikeDeclaration,
  sf: ts.SourceFile,
  propName: string,
): { mutatedWithRunKey: boolean; mutatedAny: boolean; disposed: boolean } {
  let mutatedWithRunKey = false
  let mutatedAny = false
  let disposed = false

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const receiver = node.expression.expression
      const method = node.expression.name.text
      if (isThisPropAccess(receiver, propName)) {
        if (method === 'set' || method === 'add') {
          mutatedAny = true
          const firstArg = node.arguments[0]
          if (firstArg && CLASS_KEY_ARG_RE.test(firstArg.getText(sf))) {
            mutatedWithRunKey = true
          }
        } else if (method === 'delete' || method === 'clear') {
          disposed = true
        }
      }
    } else if (ts.isPropertyAccessExpression(node) && isThisPropAccess(node, propName)) {
      const parent = node.parent
      // Handing the collection reference to a helper/collaborator (e.g. `evictRun({ ... })` or `new Worker({ ... })`)
      // transfers/shares disposal lifecycle.
      if (
        (ts.isCallExpression(parent) && parent.arguments.includes(node))
        || (ts.isPropertyAssignment(parent) && parent.initializer === node)
      ) {
        disposed = true
      }
    }
    ts.forEachChild(node, visit)
  }

  for (const member of cls.members) {
    if (ts.isPropertyDeclaration(member) && ts.isIdentifier(member.name) && member.name.text === propName) {
      continue
    }
    visit(member)
  }

  return { mutatedWithRunKey, mutatedAny, disposed }
}

export function scanFileForRunScopedState(relFile: string, content: string): RunScopedStateFinding[] {
  if (EXEMPT_FILES.has(relFile)) return []
  const sf = ts.createSourceFile(relFile, content, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const disposerRefs = collectDisposerReferencedIdentifiers(sf)
  const findings: RunScopedStateFinding[] = []

  // 1. Top-level module-scoped mutable `new Map()` / `new Set()`
  for (const stmt of sf.statements) {
    if (!ts.isVariableStatement(stmt)) continue
    for (const decl of stmt.declarationList.declarations) {
      if (!ts.isIdentifier(decl.name) || !decl.initializer) continue
      if (!ts.isNewExpression(decl.initializer)) continue
      if (!ts.isIdentifier(decl.initializer.expression)) continue
      const ctorName = decl.initializer.expression.text
      if (ctorName !== 'Map' && ctorName !== 'Set') continue
      // Only mutable empty collections (`new Map()` / `new Set()`) — skip static lookup tables (`new Set(['a', 'b'])`).
      if (decl.initializer.arguments && decl.initializer.arguments.length > 0) continue

      const varName = decl.name.text
      const typeText = decl.type ? decl.type.getText(sf) : ''
      const typeArgsText = decl.initializer.typeArguments
        ? decl.initializer.typeArguments.map(t => t.getText(sf)).join(' ')
        : ''
      const keySource = `${varName} ${typeText} ${typeArgsText}`
      if (!RUN_SCOPED_KEY_RE.test(keySource)) continue

      const line = sf.getLineAndCharacterOfPosition(decl.getStart(sf)).line + 1
      const registered = isRegisteredWithRunDisposer(sf, disposerRefs, varName)
      const excerpt = stmt.getText(sf).split(/\r?\n/)[0]!.trim().slice(0, 140)
      findings.push({
        key: `${relFile}::${varName}`,
        file: relFile,
        line,
        name: varName,
        kind: ctorName,
        scope: 'module',
        registered,
        excerpt,
      })
    }
  }

  // 2. Class-field mutable `new Map()` / `new Set()` keyed by runId / assignmentId / persona (R3-09)
  const visitClasses = (node: ts.Node): void => {
    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
      const className = node.name ? node.name.text : '<anonymous>'
      for (const member of node.members) {
        if (!ts.isPropertyDeclaration(member) || !member.initializer) continue
        if (!ts.isIdentifier(member.name) && !ts.isPrivateIdentifier(member.name)) continue
        if (!ts.isNewExpression(member.initializer)) continue
        if (!ts.isIdentifier(member.initializer.expression)) continue
        const ctorName = member.initializer.expression.text
        if (ctorName !== 'Map' && ctorName !== 'Set') continue
        if (member.initializer.arguments && member.initializer.arguments.length > 0) continue

        const propName = member.name.text
        const keyTypeText =
          member.initializer.typeArguments && member.initializer.typeArguments.length > 0
            ? member.initializer.typeArguments[0]!.getText(sf)
            : member.type && ts.isTypeReferenceNode(member.type) && member.type.typeArguments?.[0]
              ? member.type.typeArguments[0].getText(sf)
              : ''
        const keySource = `${propName} ${keyTypeText}`
        const lifecycle = analyzeClassFieldLifecycle(node, sf, propName)
        const isRunScopedField =
          lifecycle.mutatedWithRunKey || (RUN_SCOPED_KEY_RE.test(keySource) && lifecycle.mutatedAny)
        if (!isRunScopedField) continue

        const line = sf.getLineAndCharacterOfPosition(member.getStart(sf)).line + 1
        const registered = lifecycle.disposed || isRegisteredWithRunDisposer(sf, disposerRefs, propName)
        const fieldName = `${className}.${propName}`
        const excerpt = member.getText(sf).split(/\r?\n/)[0]!.trim().slice(0, 140)
        findings.push({
          key: `${relFile}::${fieldName}`,
          file: relFile,
          line,
          name: fieldName,
          kind: ctorName,
          scope: 'class-field',
          registered,
          excerpt,
        })
      }
    }
    ts.forEachChild(node, visitClasses)
  }
  visitClasses(sf)

  return findings
}

export function scanRunScopedState(
  rootDir: string,
  opts: RunScopedStateScanOptions = {},
): RunScopedStateScanResult {
  const startedAt = performance.now()
  const resolvedRoot = resolve(rootDir)
  const relDir = opts.dir ?? 'src/server'
  const absDir = resolve(resolvedRoot, relDir)
  const baselinedSet = new Set(opts.baselinedKeys ?? BASELINED_UNREGISTERED_RUN_SCOPED_STATE)
  const baselineMax = opts.baselineMax ?? baselinedSet.size

  const files: string[] = []
  collectServerTsFiles(absDir, files)

  const registered: RunScopedStateFinding[] = []
  const unregistered: RunScopedStateFinding[] = []
  for (const absFile of files) {
    const content = readFileSync(absFile, 'utf8')
    const relFile = toPosixRelative(resolvedRoot, absFile)
    for (const finding of scanFileForRunScopedState(relFile, content)) {
      if (finding.registered) registered.push(finding)
      else unregistered.push(finding)
    }
  }

  registered.sort((a, b) => a.key.localeCompare(b.key))
  unregistered.sort((a, b) => a.key.localeCompare(b.key))

  const unregisteredKeys = new Set(unregistered.map(f => f.key))
  const newViolations = unregistered.filter(f => !baselinedSet.has(f.key))
  const retiredBaselineKeys = [...baselinedSet].filter(k => !unregisteredKeys.has(k)).sort()
  const ok = newViolations.length === 0 && unregistered.length <= baselineMax
  const durationMs = Math.max(0, Math.round(performance.now() - startedAt))

  return {
    ok,
    rootDir: resolvedRoot,
    filesScanned: files.length,
    registeredCount: registered.length,
    unregisteredCount: unregistered.length,
    baselineMax,
    registered,
    unregistered,
    newViolations,
    retiredBaselineKeys,
    durationMs,
  }
}

export function formatRunScopedStateReport(result: RunScopedStateScanResult): string {
  if (result.ok) {
    const retiredNote = result.retiredBaselineKeys.length > 0
      ? ` (${result.retiredBaselineKeys.length} baseline entry(ies) retired — lower BASELINED_UNREGISTERED_RUN_SCOPED_STATE!)`
      : ''
    return (
      `run-scoped-state: PASS (${result.filesScanned} files scanned in ${result.durationMs}ms; `
      + `${result.registeredCount} registered with registerRunDisposer, `
      + `${result.unregisteredCount}/${result.baselineMax} baselined unregistered)${retiredNote}`
    )
  }
  const lines = [
    `run-scoped-state: FAIL (${result.newViolations.length} new un-registered per-run Map/Set, `
    + `${result.unregisteredCount}/${result.baselineMax} total unregistered in ${result.filesScanned} files):`,
  ]
  for (const v of result.newViolations) {
    const remediation = v.scope === 'class-field'
      ? 'back via runState.mapView(...) or delete/clear in run disposal'
      : 'register via registerRunDisposer() in src/server/run-disposers.ts'
    lines.push(`  ${v.file}:${v.line} ${v.key} (${v.kind}, ${v.scope ?? 'module'}) — ${remediation}`)
  }
  if (result.newViolations.length === 0 && result.unregisteredCount > result.baselineMax) {
    lines.push(`  unregistered count ${result.unregisteredCount} exceeds baselineMax ${result.baselineMax}`)
  }
  return lines.join('\n')
}

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

const usage = `Kovo Per-Run Module-State Ratchet Lint (R2-08)

Usage:
  node scripts/check-run-scoped-state.ts [--root <dir>] [--json] [--help]

Scans src/server/**/*.ts for top-level mutable new Map/Set keyed by run/assignment/persona
outside registerRunDisposer(...). Exits 0 at or below baseline; exits 1 on any new violation.
`

export function main(argv: string[] = process.argv.slice(2)): number {
  let rootDir = REPO_ROOT
  let json = false
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--help' || arg === '-h') {
      process.stdout.write(usage)
      return 0
    }
    if (arg === '--json') {
      json = true
      continue
    }
    if (arg === '--root') {
      const next = argv[i + 1]
      if (!next) {
        process.stderr.write('error: --root requires a directory argument\n')
        return 2
      }
      rootDir = resolve(next)
      i += 1
      continue
    }
    process.stderr.write(`error: unknown argument '${arg}'\n`)
    return 2
  }
  const result = scanRunScopedState(rootDir)
  if (json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
  } else {
    process.stdout.write(`${formatRunScopedStateReport(result)}\n`)
  }
  return result.ok ? 0 : 1
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exit(main())
}
