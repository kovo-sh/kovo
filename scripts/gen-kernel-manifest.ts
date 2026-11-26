#!/usr/bin/env node
/**
 * Confirmation-Kernel Manifest Generator (`R3-04`, `plans/claude_quality_3.md` §4).
 *
 * Uses the TypeScript compiler API (`ts.Program` + `ts.TypeChecker`) to derive the
 * canonical confirmation-kernel file manifest semantically rather than relying on a
 * static filename allowlist:
 *   1. Export-signature discovery across `src/server/*.ts`: any module exporting
 *      `assess*`, `verify*Receipt`, `evaluate*Oracle`, `evaluateClaims`,
 *      `evaluateV8OracleFamily`, or `handleProve*` is a kernel root.
 *   2. Explicit confirmation-entry roots: host-side verification orchestration modules
 *      (`replay-verifier.ts`, `floor-recipes.ts`, `exec-verify.ts`, `verify-rpc.ts`,
 *      `agent-script-proof.ts`) that dispatch verdicts/receipts/retests.
 *   3. Call-graph walk from pure verdict/oracle root functions (`verifyReceipt`,
 *      `evaluateClaims`, `verifyCompositeReceipt`, `evaluateTerminalOracle`,
 *      `evaluateV8OracleFamily`, `handleProve*`, `assess*`) via `ts.TypeChecker`,
 *      following resolved callee symbols across `src/server/*.ts` (stopping at
 *      explicitly declared non-verdict infrastructure boundaries).
 *
 * Usage:
 *   node scripts/gen-kernel-manifest.ts --check   # verify scripts/kernel-manifest.json is fresh (default)
 *   node scripts/gen-kernel-manifest.ts --write   # regenerate scripts/kernel-manifest.json
 *   node scripts/gen-kernel-manifest.ts --json    # emit manifest JSON to stdout
 */
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import ts from 'typescript'

export type KernelInclusionReason =
  | 'export_signature'
  | 'confirmation_entrypoint'
  | 'call_graph_reachable'

export interface KernelManifestEntry {
  file: string
  reasons: KernelInclusionReason[]
  matchedExports: string[]
  reachableFrom: string[]
}

export interface KernelManifest {
  version: 1
  generator: 'scripts/gen-kernel-manifest.ts'
  files: string[]
  entries: KernelManifestEntry[]
}

export interface KernelManifestFreshnessResult {
  ok: boolean
  manifestPath: string
  missingFromDisk: boolean
  addedFiles: string[]
  removedFiles: string[]
  differs: boolean
  generated: KernelManifest
}

/**
 * Semantic export-name matcher for confirmation-kernel oracle, assessor, receipt verifier,
 * and prove-handler functions in `src/server/*.ts`.
 */
export const KERNEL_EXPORT_RE =
  /^(?:assess[A-Z][A-Za-z0-9_]*|verify[A-Za-z0-9_]*Receipt|evaluate[A-Za-z0-9_]*Oracle[A-Za-z0-9_]*|evaluateClaims|evaluateV8OracleFamily|handleProve[A-Z][A-Za-z0-9_]*)$/

/**
 * Host-side verification orchestration entry points that own live confirmation/retest
 * dispatch and envelope custody.
 */
export const CONFIRMATION_ENTRY_ROOTS: ReadonlyArray<{
  file: string
  symbols: readonly string[]
}> = Object.freeze([
  { file: 'src/server/replay-verifier.ts', symbols: ['verifyReplaySpec', 'retestReplaySpec'] },
  { file: 'src/server/floor-recipes.ts', symbols: ['runFloorRecipe', 'runCut3Recipe'] },
  { file: 'src/server/exec-verify.ts', symbols: ['inspectCompositeHostOrigin', 'resolveCompositeTerminalExchange'] },
  { file: 'src/server/verify-rpc.ts', symbols: ['VerifyRpcServer'] },
  { file: 'src/server/agent-script-proof.ts', symbols: ['runAgentScriptProof', 'retestPersistedAgentScript'] },
])

/**
 * Pure verdict/oracle modules whose internal call graph is walked transitively to discover
 * helper modules participating directly in confirmation verdicts.
 */
const CALL_GRAPH_ROOT_FILES: ReadonlySet<string> = new Set([
  'src/server/proof-receipt.ts',
  'src/server/verify-claims.ts',
  'src/server/composite-receipt.ts',
  'src/server/terminal-oracle-registry.ts',
  'src/server/v8-oracle-families.ts',
  'src/server/oracle-invariants.ts',
  'src/server/verify-prove-handlers.ts',
])

/**
 * Explicit non-verdict infrastructure boundary modules where the verdict call-graph walk
 * stops (transport, storage, regex safety, redaction, budgets, custody utilities).
 */
export const NON_KERNEL_INFRA_BOUNDARY_FILES: ReadonlySet<string> = new Set([
  'src/server/safe-regex.ts',
  'src/server/egress-sanitizer.ts',
  'src/server/egress-gateway.ts',
  'src/server/derived-custody.ts',
  'src/server/run-disposers.ts',
  'src/server/run-safety-budgets.ts',
  'src/server/broker.ts',
  'src/server/store.ts',
  'src/server/schema.ts',
  'src/server/redact.ts',
  'src/server/persona-vault.ts',
  'src/server/request-admission.ts',
  'src/server/scoped-browser.ts',
  'src/server/worker-backend.ts',
  'src/server/provider.ts',
  'src/server/replay-feedback.ts',
  'src/server/deterministic-specs.ts',
  'src/server/floor-heuristics.ts',
  'src/server/verify-runner.ts',
  'src/server/access-policy-checks.ts',
  'src/server/capability-ledger.ts',
  'src/server/evidence-checks.ts',
  'src/server/exec-exchange.ts',
  'src/server/finding-fingerprint.ts',
  'src/server/response-checks.ts',
])

const TEST_FILE_RE = /(?:\.test|\.spec)\.[^./\\]+$/i

function normalizeRelPath(rootDir: string, absPath: string): string {
  return relative(rootDir, absPath).replace(/\\/g, '/')
}

function isTopLevelServerSource(relPath: string): boolean {
  if (!relPath.startsWith('src/server/')) return false
  if (relPath.slice('src/server/'.length).includes('/')) return false
  if (!relPath.endsWith('.ts')) return false
  if (TEST_FILE_RE.test(relPath)) return false
  return true
}

function listTopLevelServerFiles(rootDir: string): string[] {
  const serverDir = join(rootDir, 'src', 'server')
  if (!existsSync(serverDir)) return []
  return readdirSync(serverDir)
    .filter(name => name.endsWith('.ts') && !TEST_FILE_RE.test(name))
    .sort()
    .map(name => join(serverDir, name))
}

function extractValueExportNames(sf: ts.SourceFile): Map<string, ts.Node> {
  const out = new Map<string, ts.Node>()
  ts.forEachChild(sf, node => {
    const mods = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined
    const isExported = mods?.some(m => m.kind === ts.SyntaxKind.ExportKeyword) ?? false
    if (isExported) {
      if ((ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) && node.name) {
        out.set(node.name.text, node)
      } else if (ts.isVariableStatement(node)) {
        for (const decl of node.declarationList.declarations) {
          if (ts.isIdentifier(decl.name)) {
            out.set(decl.name.text, decl)
          }
        }
      }
      return
    }
    if (ts.isExportDeclaration(node) && !node.isTypeOnly && node.exportClause && ts.isNamedExports(node.exportClause)) {
      for (const spec of node.exportClause.elements) {
        if (!spec.isTypeOnly) {
          out.set(spec.name.text, spec)
        }
      }
    }
  })
  return out
}

function resolveTargetSymbol(checker: ts.TypeChecker, node: ts.Node): ts.Symbol | undefined {
  const sym = checker.getSymbolAtLocation(node)
  if (!sym) return undefined
  if ((sym.flags & ts.SymbolFlags.Alias) !== 0) {
    try {
      return checker.getAliasedSymbol(sym)
    } catch {
      return sym
    }
  }
  return sym
}

function unwrapCallableDeclaration(decl: ts.Declaration): ts.Node | null {
  if (
    ts.isFunctionDeclaration(decl) ||
    ts.isMethodDeclaration(decl) ||
    ts.isArrowFunction(decl) ||
    ts.isFunctionExpression(decl) ||
    ts.isClassDeclaration(decl)
  ) {
    return decl
  }
  if (ts.isVariableDeclaration(decl) && decl.initializer) {
    return decl.initializer
  }
  return null
}

/**
 * Scan all `src/server/*.ts` files with `ts.Program` and return every file exporting
 * a symbol matching `KERNEL_EXPORT_RE` (useful for export-staleness verification).
 */
export function scanKernelExportFiles(rootDir: string = REPO_ROOT): Map<string, string[]> {
  const absRoot = resolve(rootDir)
  const files = listTopLevelServerFiles(absRoot)
  const program = ts.createProgram(files, {
    target: ts.ScriptTarget.ESNext,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    allowImportingTsExtensions: true,
    noEmit: true,
    skipLibCheck: true,
  })
  const matched = new Map<string, string[]>()
  for (const sf of program.getSourceFiles()) {
    const rel = normalizeRelPath(absRoot, sf.fileName)
    if (!isTopLevelServerSource(rel)) continue
    const exportsMap = extractValueExportNames(sf)
    const hits = [...exportsMap.keys()].filter(name => KERNEL_EXPORT_RE.test(name)).sort()
    if (hits.length > 0) {
      matched.set(rel, hits)
    }
  }
  return matched
}

/**
 * Generate the canonical confirmation-kernel manifest for `rootDir` using `ts.Program`
 * export discovery and `ts.TypeChecker` call-graph traversal.
 */
export function generateKernelManifest(rootDir: string = REPO_ROOT): KernelManifest {
  const absRoot = resolve(rootDir)
  const files = listTopLevelServerFiles(absRoot)
  const program = ts.createProgram(files, {
    target: ts.ScriptTarget.ESNext,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    allowImportingTsExtensions: true,
    noEmit: true,
    skipLibCheck: true,
  })
  const checker = program.getTypeChecker()

  const sourceByRel = new Map<string, ts.SourceFile>()
  const exportsByRel = new Map<string, Map<string, ts.Node>>()
  for (const sf of program.getSourceFiles()) {
    const rel = normalizeRelPath(absRoot, sf.fileName)
    if (!isTopLevelServerSource(rel)) continue
    sourceByRel.set(rel, sf)
    exportsByRel.set(rel, extractValueExportNames(sf))
  }

  const reasonsByFile = new Map<string, Set<KernelInclusionReason>>()
  const matchedExportsByFile = new Map<string, Set<string>>()
  const reachableFromByFile = new Map<string, Set<string>>()

  const ensureFile = (rel: string): void => {
    if (!reasonsByFile.has(rel)) reasonsByFile.set(rel, new Set())
    if (!matchedExportsByFile.has(rel)) matchedExportsByFile.set(rel, new Set())
    if (!reachableFromByFile.has(rel)) reachableFromByFile.set(rel, new Set())
  }

  // Seed 1: AST export-signature roots across all top-level src/server/*.ts files.
  const worklist: Array<{ node: ts.Node; originLabel: string }> = []
  const visitedDecls = new Set<ts.Node>()

  for (const [rel, exportsMap] of [...exportsByRel.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const hits = [...exportsMap.keys()].filter(name => KERNEL_EXPORT_RE.test(name)).sort()
    if (hits.length === 0) continue
    ensureFile(rel)
    reasonsByFile.get(rel)!.add('export_signature')
    for (const symName of hits) {
      matchedExportsByFile.get(rel)!.add(symName)
      if (CALL_GRAPH_ROOT_FILES.has(rel)) {
        const decl = exportsMap.get(symName)
        if (decl) {
          worklist.push({ node: decl, originLabel: `${rel}::${symName}` })
        }
      }
    }
  }

  // Seed 2: Explicit confirmation-entry roots (verified to exist in ts.Program).
  for (const entry of CONFIRMATION_ENTRY_ROOTS) {
    const exportsMap = exportsByRel.get(entry.file)
    if (!exportsMap) continue
    const presentSymbols = entry.symbols.filter(s => exportsMap.has(s))
    if (presentSymbols.length === 0) continue
    ensureFile(entry.file)
    reasonsByFile.get(entry.file)!.add('confirmation_entrypoint')
    for (const symName of presentSymbols) {
      matchedExportsByFile.get(entry.file)!.add(symName)
    }
  }

  // Seed 3: Transitive call-graph walk from pure verdict/oracle root functions via ts.TypeChecker.
  while (worklist.length > 0) {
    const { node, originLabel } = worklist.pop()!
    if (visitedDecls.has(node)) continue
    visitedDecls.add(node)

    const walk = (curr: ts.Node): void => {
      if (ts.isCallExpression(curr) || ts.isNewExpression(curr)) {
        const calleeExpr = curr.expression
        const targetNode = ts.isPropertyAccessExpression(calleeExpr) ? calleeExpr.name : calleeExpr
        const sym = resolveTargetSymbol(checker, targetNode)
        if (sym?.declarations) {
          for (const decl of sym.declarations) {
            const targetSf = decl.getSourceFile()
            const targetRel = normalizeRelPath(absRoot, targetSf.fileName)
            if (!isTopLevelServerSource(targetRel)) continue
            if (NON_KERNEL_INFRA_BOUNDARY_FILES.has(targetRel)) continue
            ensureFile(targetRel)
            reasonsByFile.get(targetRel)!.add('call_graph_reachable')
            if (!originLabel.startsWith(`${targetRel}::`)) {
              reachableFromByFile.get(targetRel)!.add(originLabel)
            }
            const callable = unwrapCallableDeclaration(decl)
            if (callable && !visitedDecls.has(callable)) {
              worklist.push({ node: callable, originLabel })
            }
          }
        }
      }
      ts.forEachChild(curr, walk)
    }
    walk(node)
  }

  const sortedFiles = [...reasonsByFile.keys()].sort()
  const entries: KernelManifestEntry[] = sortedFiles.map(file => ({
    file,
    reasons: [...reasonsByFile.get(file)!].sort() as KernelInclusionReason[],
    matchedExports: [...matchedExportsByFile.get(file)!].sort(),
    reachableFrom: [...reachableFromByFile.get(file)!].sort(),
  }))

  return {
    version: 1,
    generator: 'scripts/gen-kernel-manifest.ts',
    files: sortedFiles,
    entries,
  }
}

export function serializeKernelManifest(manifest: KernelManifest): string {
  return `${JSON.stringify(manifest, null, 2)}\n`
}

export function checkKernelManifestFreshness(
  rootDir: string = REPO_ROOT,
  manifestRelPath = 'scripts/kernel-manifest.json',
): KernelManifestFreshnessResult {
  const absRoot = resolve(rootDir)
  const manifestPath = join(absRoot, manifestRelPath)
  const generated = generateKernelManifest(absRoot)
  if (!existsSync(manifestPath)) {
    return {
      ok: false,
      manifestPath,
      missingFromDisk: true,
      addedFiles: [...generated.files],
      removedFiles: [],
      differs: true,
      generated,
    }
  }
  const existingRaw = readFileSync(manifestPath, 'utf8')
  const expectedRaw = serializeKernelManifest(generated)
  let existingFiles: string[] = []
  try {
    const parsed = JSON.parse(existingRaw) as { files?: unknown }
    if (Array.isArray(parsed.files)) {
      existingFiles = parsed.files.filter((x): x is string => typeof x === 'string')
    }
  } catch {
    existingFiles = []
  }
  const existingSet = new Set(existingFiles)
  const generatedSet = new Set(generated.files)
  const addedFiles = generated.files.filter(f => !existingSet.has(f))
  const removedFiles = existingFiles.filter(f => !generatedSet.has(f))
  const differs = existingRaw !== expectedRaw
  return {
    ok: !differs,
    manifestPath,
    missingFromDisk: false,
    addedFiles,
    removedFiles,
    differs,
    generated,
  }
}

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

const usage = `Kovo Hunter Confirmation-Kernel Manifest Generator (R3-04)

Usage:
  node scripts/gen-kernel-manifest.ts --check [--root <dir>]
  node scripts/gen-kernel-manifest.ts --write [--root <dir>]
  node scripts/gen-kernel-manifest.ts --json  [--root <dir>]
`

export function main(argv: string[] = process.argv.slice(2)): number {
  let rootDir = REPO_ROOT
  let mode: 'check' | 'write' | 'json' = 'check'
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '-h' || arg === '--help') {
      process.stdout.write(usage)
      return 0
    }
    if (arg === '--check') { mode = 'check'; continue }
    if (arg === '--write') { mode = 'write'; continue }
    if (arg === '--json') { mode = 'json'; continue }
    if (arg === '--root') {
      const next = argv[i + 1]
      if (!next) { process.stderr.write('error: --root requires a directory\n'); return 2 }
      rootDir = resolve(next); i += 1; continue
    }
    process.stderr.write(`error: unknown argument '${arg}'\n`)
    return 2
  }

  if (mode === 'json') {
    const manifest = generateKernelManifest(rootDir)
    process.stdout.write(serializeKernelManifest(manifest))
    return 0
  }

  if (mode === 'write') {
    const manifest = generateKernelManifest(rootDir)
    const outPath = join(rootDir, 'scripts', 'kernel-manifest.json')
    writeFileSync(outPath, serializeKernelManifest(manifest), 'utf8')
    process.stdout.write(`kernel-manifest: WROTE ${manifest.files.length} confirmation-kernel files to scripts/kernel-manifest.json\n`)
    return 0
  }

  const res = checkKernelManifestFreshness(rootDir)
  if (res.ok) {
    process.stdout.write(`kernel-manifest: PASS (${res.generated.files.length} confirmation-kernel files fresh)\n`)
    return 0
  }
  if (res.missingFromDisk) {
    process.stderr.write('kernel-manifest: FAIL (scripts/kernel-manifest.json missing; run "node scripts/gen-kernel-manifest.ts --write")\n')
  } else {
    const parts: string[] = []
    if (res.addedFiles.length > 0) parts.push(`missing=${res.addedFiles.join(',')}`)
    if (res.removedFiles.length > 0) parts.push(`extra=${res.removedFiles.join(',')}`)
    if (parts.length === 0) parts.push('manifest metadata drifted')
    process.stderr.write(
      `kernel-manifest: FAIL (scripts/kernel-manifest.json is stale: ${parts.join('; ')}; run "node scripts/gen-kernel-manifest.ts --write")\n`,
    )
  }
  return 1
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(resolve(process.argv[1])).href : false
if (isMain) {
  process.exit(main())
}
