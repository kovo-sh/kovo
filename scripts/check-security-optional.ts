#!/usr/bin/env node
/**
 * R3-08 Security-Optional & Test-Seam Boundary Ratchet (`scripts/check-security-optional.ts`).
 *
 * TypeScript AST lint over `src/server/**` enforcing that security-critical guard inputs
 * cannot quietly regress into opt-in optional parameters, fail-open early returns, or
 * test-only bypass switches reachable from production code:
 *
 *   1. ZERO-TOLERANCE FORBIDDEN TEST SEAMS (`forbidden_test_seam`):
 *      Rejects any parameter/property matching `allowUnscoped*`, `*ForTest` safety switches,
 *      `bypass(Scope|Approval|Egress|Auth|Guard|Security)*`, `skip(Scope|Approval|Egress|Auth|Guard|Security)*`,
 *      `disable(Scope|Approval|Egress|Auth|Guard|Security)*`, or `unsafeSkip*`/`insecureSkip*`.
 *   2. ZERO-TOLERANCE FAIL-OPEN EARLY RETURNS (`fail_open_early_return`):
 *      Rejects `if (!x) return false` / `if (!x) return true` / `if (!x) return { allowed: true }` /
 *      `if (x == null) return false` where `x` is a registered security guard input.
 *   3. ZERO-TOLERANCE PRODUCTION -> TEST-HELPER IMPORT BOUNDARY (`test_helper_import_in_src`):
 *      Rejects any `import` / `export ... from` / `import(...)` / `require(...)` from `src/**`
 *      that targets `tests/**` (including `tests/helpers/browser-session-test-factory.ts`) or
 *      any `*.test.*` / `*.spec.*` module.
 *   4. MONOTONE REMOVAL-ONLY BASELINE FOR OPTIONAL SECURITY INPUTS (`optional_security_input`,
 *      `permissive_flag`):
 *      Flags optional (`?:`) or default-undefined/false declarations of security-critical names
 *      in `SECURITY_OPTION_REGISTRY` across `src/server/**`. Pre-existing debt is frozen in
 *      `scripts/security-optional-baseline.json` by stable structural key
 *      (`<file>::<container>::<name>`); ZERO new optional security inputs are allowed, and
 *      `--write-baseline` is strictly removal-only.
 *   5. PRODUCTION-ENTRY GUARD TEST COVERAGE (`missing_entry_guard_test`):
 *      Verifies that every security guard family in `SECURITY_GUARD_ENTRY_REGISTRY` has at
 *      least one production-entry test under `tests/security-entry-*.test.ts`.
 *
 * Usage:
 *   node scripts/check-security-optional.ts
 *   node scripts/check-security-optional.ts --json
 *   node scripts/check-security-optional.ts --write-baseline   # removal-only prune
 */
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, posix, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import ts from 'typescript'

const EXCLUDED_DIRS = new Set(['node_modules', '.git', 'dist', '.output', '.nitro', '.vinxi', '.tanstack', 'coverage'])
const TEST_FILE_RE = /(?:^|\/)(?:tests?|__tests__)\/|(?:\.test|\.spec)\.[^./\\]+$/i
const TS_EXT_RE = /\.(?:ts|tsx|mts|cts)$/i

export const BASELINE_REL_PATH = 'scripts/security-optional-baseline.json'

/**
 * Security-critical parameter/option names governed by R3-08.
 * Adding an optional (`?:`) or fail-open declaration for any of these in `src/server/**`
 * is rejected unless pre-existing in the removal-only baseline.
 */
export const SECURITY_OPTION_REGISTRY: ReadonlySet<string> = new Set([
  // Browser-session & scope guards
  'scopePolicy',
  'modifiedPaths',
  'verifyPathModifiedByRun',
  'requireScopePolicy',
  // Egress, sandbox & kill-switch guards
  'egressGuard',
  'egressPolicy',
  'killSwitch',
  // Approval & judge guards
  'judge',
  'approvalLease',
  'leaseAuthorizes',
  // Host-minted oracle / stamp / challenge inputs
  'hostMintedOracle',
  'stampedChallenge',
  'hostBooleanPair',
  'hostExpressionChallenge',
  'hostTimingChallenge',
  'hostRedirectCanaryHost',
  // Secret-needle / scrubbing inputs
  'secretNeedles',
  'personaSecretNeedles',
])

/**
 * Security guard families that MUST each have at least one production-entry test
 * in `tests/security-entry-*.test.ts`.
 */
export interface SecurityGuardEntrySpec {
  readonly id: string
  readonly symbol: string
  readonly file: string
  readonly entryPoint: string
}

export const SECURITY_GUARD_ENTRY_REGISTRY: readonly SecurityGuardEntrySpec[] = Object.freeze([
  {
    id: 'browser-session-refresher',
    symbol: 'refreshBrowserSession',
    file: 'src/server/browser-session-auth.ts',
    entryPoint: 'PersonaAuthManager.authenticatePersona',
  },
  {
    id: 'scope-origin-admission',
    symbol: 'assertOriginsWithinProjectScope',
    file: 'src/server/persona-vault.ts',
    entryPoint: 'createBrowserSessionPersona / registerBrowserSessionPersonaFromAction',
  },
  {
    id: 'approval-lease-authority',
    symbol: 'authorizeStateChange',
    file: 'src/server/approval-judge.ts',
    entryPoint: 'authorizeStateChange / evaluateTier3Approval',
  },
  {
    id: 'provider-stream-sanitizer',
    symbol: 'sanitizeProviderStream',
    file: 'src/server/provider-stream.ts',
    entryPoint: 'sanitizeProviderStream / scrubOutboundProviderRequest',
  },
  {
    id: 'persona-secret-needles',
    symbol: 'buildPersonaSecretNeedles',
    file: 'src/server/persona-vault.ts',
    entryPoint: 'VerifyRpcServer / createEgressSanitizer',
  },
  {
    id: 'host-minted-oracle-stamps',
    symbol: 'verifyReceipt',
    file: 'src/server/proof-receipt.ts',
    entryPoint: 'verifyReceipt / HostMintedOracle',
  },
])

/**
 * Zero-tolerance test-seam / safety-bypass flag names that may NEVER exist in `src/server/**`.
 */
export const FORBIDDEN_TEST_SEAM_RE =
  /^(?:allowUnscoped\w*|bypass(?:Scope|Approval|Egress|Auth|Guard|Security)\w*|skip(?:Scope|Approval|Egress|Auth|Guard|Security)\w*|disable(?:Scope|Approval|Egress|Auth|Guard|Security)\w*|unsafeSkip\w*|insecureSkip\w*|\w+(?:Refresh|Scope|Guard|Check|Policy|Auth)ForTest)$/i

/**
 * General permissive skip/bypass parameter/property names tracked under the removal-only baseline.
 */
export const PERMISSIVE_FLAG_RE = /^(?:skip\w*Check|bypass\w+)$/i

export type SecurityOptionalHitKind =
  | 'optional_security_input'
  | 'permissive_flag'
  | 'forbidden_test_seam'
  | 'fail_open_early_return'
  | 'test_helper_import_in_src'
  | 'missing_entry_guard_test'

export interface SecurityOptionalHit {
  key: string
  file: string
  line: number
  kind: SecurityOptionalHitKind
  name: string
  container: string
  detail: string
}

export interface SecurityOptionalBaseline {
  version: 1
  description: string
  baselinedKeys: string[]
}

export interface SecurityOptionalAuditResult {
  ok: boolean
  rootDir: string
  filesScanned: number
  srcFilesScannedForTestImports: number
  hits: SecurityOptionalHit[]
  zeroToleranceHits: SecurityOptionalHit[]
  newBaselinedViolations: SecurityOptionalHit[]
  baselinedHitsCount: number
  baselineTotal: number
  resolvedBaselineKeys: string[]
  entryGuardCoverage: Array<{ id: string; covered: boolean; testFiles: string[] }>
  regressions: string[]
  durationMs: number
}

function toPosix(p: string): string {
  return sep === '/' ? p : p.split(sep).join(posix.sep)
}

function collectTsFiles(rootDir: string, relDir: string, includeTests: boolean): string[] {
  const absDir = join(rootDir, relDir)
  if (!existsSync(absDir)) return []
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
      } else if (entry.isFile() && TS_EXT_RE.test(entry.name) && !entry.name.endsWith('.d.ts')) {
        const rel = toPosix(relative(rootDir, full))
        if (includeTests || !TEST_FILE_RE.test(rel)) out.push(rel)
      }
    }
  }
  walk(absDir)
  return out
}

function propNameText(name: ts.PropertyName | ts.BindingName): string | null {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNoSubstitutionTemplateLiteral(name)) {
    return name.text
  }
  return null
}

function describeEnclosingContainer(node: ts.Node): string {
  const parts: string[] = []
  let curr: ts.Node | undefined = node.parent
  while (curr) {
    if (ts.isInterfaceDeclaration(curr)) {
      parts.push(curr.name.text)
    } else if (ts.isTypeAliasDeclaration(curr)) {
      parts.push(curr.name.text)
    } else if (ts.isClassDeclaration(curr) && curr.name) {
      parts.push(curr.name.text)
    } else if (ts.isFunctionDeclaration(curr) && curr.name) {
      parts.push(curr.name.text)
    } else if (ts.isMethodDeclaration(curr) || ts.isMethodSignature(curr)) {
      const m = propNameText(curr.name)
      if (m) parts.push(m)
    } else if (ts.isConstructorDeclaration(curr)) {
      parts.push('constructor')
    } else if (ts.isVariableDeclaration(curr) && ts.isIdentifier(curr.name)) {
      parts.push(curr.name.text)
    } else if (ts.isPropertySignature(curr) || ts.isPropertyAssignment(curr)) {
      const p = propNameText(curr.name)
      if (p) parts.push(p)
    } else if (ts.isParameter(curr) && ts.isIdentifier(curr.name)) {
      parts.push(`param:${curr.name.text}`)
    }
    curr = curr.parent
  }
  if (parts.length === 0) return '<module>'
  return parts.reverse().join('.')
}

function isPermissiveDefaultInitializer(init: ts.Expression | undefined): boolean {
  if (!init) return false
  if (init.kind === ts.SyntaxKind.UndefinedKeyword || init.kind === ts.SyntaxKind.NullKeyword) return true
  if (init.kind === ts.SyntaxKind.FalseKeyword) return true
  if (ts.isIdentifier(init) && init.text === 'undefined') return true
  if (ts.isArrayLiteralExpression(init) && init.elements.length === 0) return true
  return false
}

function extractNegatedSecurityIdentifier(expr: ts.Expression): string | null {
  let inner: ts.Expression = expr
  while (ts.isParenthesizedExpression(inner)) inner = inner.expression

  // `!x` or `!obj.x`
  if (ts.isPrefixUnaryExpression(inner) && inner.operator === ts.SyntaxKind.ExclamationToken) {
    const operand = inner.operand
    if (ts.isIdentifier(operand) && SECURITY_OPTION_REGISTRY.has(operand.text)) return operand.text
    if (ts.isPropertyAccessExpression(operand) && SECURITY_OPTION_REGISTRY.has(operand.name.text)) return operand.name.text
    return null
  }

  // `x == null` / `x === undefined` / `obj.x == null`
  if (
    ts.isBinaryExpression(inner)
    && (inner.operatorToken.kind === ts.SyntaxKind.EqualsEqualsToken
      || inner.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken)
  ) {
    const checkPair = (lhs: ts.Expression, rhs: ts.Expression): string | null => {
      const rhsIsNullish =
        rhs.kind === ts.SyntaxKind.NullKeyword
        || (ts.isIdentifier(rhs) && rhs.text === 'undefined')
      if (!rhsIsNullish) return null
      if (ts.isIdentifier(lhs) && SECURITY_OPTION_REGISTRY.has(lhs.text)) return lhs.text
      if (ts.isPropertyAccessExpression(lhs) && SECURITY_OPTION_REGISTRY.has(lhs.name.text)) return lhs.name.text
      return null
    }
    return checkPair(inner.left, inner.right) ?? checkPair(inner.right, inner.left)
  }

  return null
}

function isFailOpenReturnStatement(stmt: ts.Statement): string | null {
  let target: ts.Statement | undefined = stmt
  if (ts.isBlock(stmt)) {
    if (stmt.statements.length !== 1) return null
    target = stmt.statements[0]
  }
  if (!target || !ts.isReturnStatement(target) || !target.expression) return null
  const expr = target.expression
  if (expr.kind === ts.SyntaxKind.FalseKeyword) return 'return false'
  if (expr.kind === ts.SyntaxKind.TrueKeyword) return 'return true'
  if (ts.isObjectLiteralExpression(expr)) {
    for (const prop of expr.properties) {
      if (!ts.isPropertyAssignment(prop)) continue
      const key = propNameText(prop.name)
      if ((key === 'allowed' || key === 'ok' || key === 'approved') && prop.initializer.kind === ts.SyntaxKind.TrueKeyword) {
        return `return { ${key}: true }`
      }
    }
  }
  return null
}

function isTestImportSpecifier(rootDir: string, fromRel: string, spec: string): boolean {
  if (!spec.startsWith('.')) return false
  const resolvedAbs = resolve(rootDir, dirname(fromRel), spec)
  const resolvedRel = toPosix(relative(rootDir, resolvedAbs))
  if (resolvedRel === 'tests' || resolvedRel.startsWith('tests/') || resolvedRel.includes('/tests/')) {
    return true
  }
  if (TEST_FILE_RE.test(resolvedRel)) return true
  return false
}

export function scanSourceForTestHelperImports(rootDir: string): {
  filesScanned: number
  hits: SecurityOptionalHit[]
} {
  const srcFiles = collectTsFiles(rootDir, 'src', false)
  const hits: SecurityOptionalHit[] = []

  for (const rel of srcFiles) {
    const abs = join(rootDir, rel)
    const src = readFileSync(abs, 'utf8')
    const sf = ts.createSourceFile(abs, src, ts.ScriptTarget.Latest, true)

    const recordIfForbidden = (spec: string, node: ts.Node) => {
      if (!isTestImportSpecifier(rootDir, rel, spec)) return
      const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
      hits.push({
        key: `${rel}::import::${spec}`,
        file: rel,
        line,
        kind: 'test_helper_import_in_src',
        name: spec,
        container: '<module>',
        detail: `Production source file "${rel}" must never import test helper/module "${spec}".`,
      })
    }

    const visit = (node: ts.Node) => {
      if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
        recordIfForbidden(node.moduleSpecifier.text, node)
      } else if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
        recordIfForbidden(node.moduleSpecifier.text, node)
      } else if (ts.isCallExpression(node) && node.arguments.length > 0 && ts.isStringLiteral(node.arguments[0]!)) {
        const isDynImport = node.expression.kind === ts.SyntaxKind.ImportKeyword
        const isRequire = ts.isIdentifier(node.expression) && node.expression.text === 'require'
        if (isDynImport || isRequire) {
          recordIfForbidden(node.arguments[0]!.text, node)
        }
      }
      ts.forEachChild(node, visit)
    }
    visit(sf)
  }

  return { filesScanned: srcFiles.length, hits }
}

export function scanEntryGuardTestCoverage(rootDir: string): Array<{
  id: string
  covered: boolean
  testFiles: string[]
}> {
  const testsDir = join(rootDir, 'tests')
  const entryTestFiles: Array<{ rel: string; text: string }> = []
  if (existsSync(testsDir)) {
    for (const entry of readdirSync(testsDir, { withFileTypes: true })) {
      if (!entry.isFile()) continue
      if (!/^security-entry-.*\.test\.ts$/.test(entry.name)) continue
      const rel = `tests/${entry.name}`
      entryTestFiles.push({ rel, text: readFileSync(join(testsDir, entry.name), 'utf8') })
    }
  }

  return SECURITY_GUARD_ENTRY_REGISTRY.map(spec => {
    const matchedFiles = entryTestFiles
      .filter(f => f.text.includes(spec.id) && f.text.includes(spec.symbol))
      .map(f => f.rel)
      .sort()
    return {
      id: spec.id,
      covered: matchedFiles.length > 0,
      testFiles: matchedFiles,
    }
  })
}

export function loadBaseline(rootDir: string, baselinePath = join(rootDir, BASELINE_REL_PATH)): Set<string> {
  if (!existsSync(baselinePath)) return new Set()
  const raw = JSON.parse(readFileSync(baselinePath, 'utf8')) as Partial<SecurityOptionalBaseline>
  const keys = Array.isArray(raw.baselinedKeys) ? raw.baselinedKeys.filter((k): k is string => typeof k === 'string') : []
  return new Set(keys)
}

export function scanSecurityOptional(
  rootDir: string,
  options: { baselinePath?: string; skipEntryCoverage?: boolean } = {},
): SecurityOptionalAuditResult {
  const t0 = Date.now()
  const serverFiles = collectTsFiles(rootDir, 'src/server', false)
  const hits: SecurityOptionalHit[] = []

  for (const rel of serverFiles) {
    const abs = join(rootDir, rel)
    if (!statSync(abs).isFile()) continue
    const src = readFileSync(abs, 'utf8')
    const sf = ts.createSourceFile(abs, src, ts.ScriptTarget.Latest, true)

    // Deduplicate identical keys in a single file with an occurrence suffix if a function overload repeats.
    const seenKeyCounts = new Map<string, number>()
    const makeKey = (container: string, name: string, kind: SecurityOptionalHitKind): string => {
      const base = `${rel}::${container}::${name}${kind === 'fail_open_early_return' ? '::early_return' : ''}`
      const n = (seenKeyCounts.get(base) ?? 0) + 1
      seenKeyCounts.set(base, n)
      return n === 1 ? base : `${base}#${n}`
    }

    const visit = (node: ts.Node) => {
      if (ts.isPropertySignature(node) || ts.isPropertyDeclaration(node) || ts.isParameter(node)) {
        const name = propNameText(node.name)
        if (name) {
          const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
          const container = describeEnclosingContainer(node)
          if (FORBIDDEN_TEST_SEAM_RE.test(name)) {
            hits.push({
              key: makeKey(container, name, 'forbidden_test_seam'),
              file: rel,
              line,
              kind: 'forbidden_test_seam',
              name,
              container,
              detail: `Forbidden test-seam / safety-bypass flag "${name}" in ${rel}:${line} (${container}).`,
            })
          } else if (PERMISSIVE_FLAG_RE.test(name)) {
            hits.push({
              key: makeKey(container, name, 'permissive_flag'),
              file: rel,
              line,
              kind: 'permissive_flag',
              name,
              container,
              detail: `Permissive skip/bypass flag "${name}" in ${rel}:${line} (${container}).`,
            })
          } else if (SECURITY_OPTION_REGISTRY.has(name)) {
            const isOptional = Boolean(node.questionToken)
            const hasPermissiveDefault = ts.isParameter(node) && isPermissiveDefaultInitializer(node.initializer)
            if (isOptional || hasPermissiveDefault) {
              hits.push({
                key: makeKey(container, name, 'optional_security_input'),
                file: rel,
                line,
                kind: 'optional_security_input',
                name,
                container,
                detail: `Optional/default-permissive security input "${name}" in ${rel}:${line} (${container}).`,
              })
            }
          }
        }
      } else if (ts.isIfStatement(node)) {
        const secName = extractNegatedSecurityIdentifier(node.expression)
        if (secName) {
          const earlyReturnDesc = isFailOpenReturnStatement(node.thenStatement)
          if (earlyReturnDesc) {
            const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
            const container = describeEnclosingContainer(node)
            hits.push({
              key: makeKey(container, secName, 'fail_open_early_return'),
              file: rel,
              line,
              kind: 'fail_open_early_return',
              name: secName,
              container,
              detail: `Fail-open early return on missing "${secName}" (${earlyReturnDesc}) in ${rel}:${line} (${container}).`,
            })
          }
        }
      }
      ts.forEachChild(node, visit)
    }
    visit(sf)
  }

  // 2. Scan all production `src/**` for forbidden imports of `tests/**` helpers.
  const testImportScan = scanSourceForTestHelperImports(rootDir)
  hits.push(...testImportScan.hits)

  // 3. Verify every security guard family has at least one production-entry test.
  const entryGuardCoverage = options.skipEntryCoverage
    ? SECURITY_GUARD_ENTRY_REGISTRY.map(spec => ({ id: spec.id, covered: true, testFiles: [] as string[] }))
    : scanEntryGuardTestCoverage(rootDir)
  for (const cov of entryGuardCoverage) {
    if (!cov.covered) {
      const spec = SECURITY_GUARD_ENTRY_REGISTRY.find(s => s.id === cov.id)!
      hits.push({
        key: `entry-coverage::${cov.id}`,
        file: spec.file,
        line: 1,
        kind: 'missing_entry_guard_test',
        name: spec.symbol,
        container: spec.entryPoint,
        detail: `Security guard "${cov.id}" (${spec.file}::${spec.symbol} via ${spec.entryPoint}) has no production-entry test in tests/security-entry-*.test.ts.`,
      })
    }
  }

  const baselineKeys = loadBaseline(rootDir, options.baselinePath)
  const zeroToleranceHits: SecurityOptionalHit[] = []
  const newBaselinedViolations: SecurityOptionalHit[] = []
  const currentBaselinedSet = new Set<string>()
  let baselinedHitsCount = 0

  for (const hit of hits) {
    if (
      hit.kind === 'forbidden_test_seam'
      || hit.kind === 'fail_open_early_return'
      || hit.kind === 'test_helper_import_in_src'
      || hit.kind === 'missing_entry_guard_test'
    ) {
      zeroToleranceHits.push(hit)
    } else if (baselineKeys.has(hit.key)) {
      baselinedHitsCount += 1
      currentBaselinedSet.add(hit.key)
    } else {
      newBaselinedViolations.push(hit)
    }
  }

  const resolvedBaselineKeys = [...baselineKeys].filter(k => !currentBaselinedSet.has(k)).sort()
  const regressions: string[] = []
  for (const hit of zeroToleranceHits) {
    regressions.push(`[ZERO-TOLERANCE:${hit.kind}] ${hit.detail}`)
  }
  for (const hit of newBaselinedViolations) {
    regressions.push(`[NEW-SECURITY-OPTIONAL:${hit.kind}] ${hit.detail} (key: ${hit.key})`)
  }

  return {
    ok: regressions.length === 0,
    rootDir,
    filesScanned: serverFiles.length,
    srcFilesScannedForTestImports: testImportScan.filesScanned,
    hits,
    zeroToleranceHits,
    newBaselinedViolations,
    baselinedHitsCount,
    baselineTotal: baselineKeys.size,
    resolvedBaselineKeys,
    entryGuardCoverage,
    regressions,
    durationMs: Date.now() - t0,
  }
}

export function writeRemovalOnlyBaseline(
  rootDir: string,
  options: { baselinePath?: string; init?: boolean } = {},
): { writtenKeys: string[]; prunedCount: number } {
  const baselinePath = options.baselinePath ?? join(rootDir, BASELINE_REL_PATH)
  const result = scanSecurityOptional(rootDir, { baselinePath, skipEntryCoverage: true })

  if (result.zeroToleranceHits.length > 0) {
    throw new Error(
      `Cannot write baseline while ${result.zeroToleranceHits.length} zero-tolerance violation(s) exist:\n`
      + result.zeroToleranceHits.map(h => `  - ${h.detail}`).join('\n'),
    )
  }

  const currentBaselinedCandidates = result.hits
    .filter(h => h.kind === 'optional_security_input' || h.kind === 'permissive_flag')
    .map(h => h.key)
    .sort()

  const existing = loadBaseline(rootDir, baselinePath)
  let nextKeys: string[]
  if (options.init && !existsSync(baselinePath)) {
    nextKeys = [...new Set(currentBaselinedCandidates)].sort()
  } else {
    // Strictly removal-only: refuse to add keys not already present in the baseline.
    const additions = currentBaselinedCandidates.filter(k => !existing.has(k))
    if (additions.length > 0) {
      throw new Error(
        `Refusing to add ${additions.length} new optional security input(s) to removal-only baseline:\n`
        + additions.map(k => `  - ${k}`).join('\n'),
      )
    }
    const currentSet = new Set(currentBaselinedCandidates)
    nextKeys = [...existing].filter(k => currentSet.has(k)).sort()
  }

  const prunedCount = Math.max(0, existing.size - nextKeys.length)
  const payload: SecurityOptionalBaseline = {
    version: 1,
    description: 'R3-08 removal-only baseline of pre-existing optional security parameters/permissive flags in src/server/**. Zero new entries allowed; prune as debt is removed.',
    baselinedKeys: nextKeys,
  }
  writeFileSync(baselinePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8')
  return { writtenKeys: nextKeys, prunedCount }
}

function main() {
  const args = process.argv.slice(2)
  const jsonMode = args.includes('--json')
  const writeBaseline = args.includes('--write-baseline')
  const initBaseline = args.includes('--init-baseline')
  const rootDir = resolve(fileURLToPath(new URL('..', import.meta.url)))

  if (writeBaseline || initBaseline) {
    try {
      const res = writeRemovalOnlyBaseline(rootDir, { init: initBaseline })
      process.stdout.write(
        `Wrote ${BASELINE_REL_PATH}: ${res.writtenKeys.length} baselined key(s) (${res.prunedCount} pruned)\n`,
      )
      process.exit(0)
    } catch (err) {
      process.stderr.write(`FAIL: ${err instanceof Error ? err.message : String(err)}\n`)
      process.exit(1)
    }
  }

  const result = scanSecurityOptional(rootDir)
  if (jsonMode) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
  } else if (result.ok) {
    const pruneHint = result.resolvedBaselineKeys.length > 0
      ? ` (${result.resolvedBaselineKeys.length} resolved baseline entry(ies) ready to prune via --write-baseline)`
      : ''
    process.stdout.write(
      `security-optional: PASS (${result.filesScanned} server files, ${result.srcFilesScannedForTestImports} src import-boundary files, `
      + `${result.baselinedHitsCount}/${result.baselineTotal} baselined debt, 0 new optional security inputs, `
      + `0 forbidden test seams, 0 fail-open early returns, `
      + `${result.entryGuardCoverage.filter(c => c.covered).length}/${result.entryGuardCoverage.length} entry guards covered in ${result.durationMs}ms)${pruneHint}\n`,
    )
  } else {
    process.stderr.write(`security-optional: FAIL (${result.regressions.length} violation(s)):\n`)
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
