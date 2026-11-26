#!/usr/bin/env node
/**
 * Unwired-Export, Runtime Import-Cycle & ARCHITECTURE.md Citation Ratchet (CQ-11).
 *
 * Zero-network, dependency-light static check powered by the local TypeScript compiler API:
 *   1. Runtime (value-level) import cycle check over `src/**` (excluding tests):
 *      - Fails on any NEW cycle not baselined in `scripts/unwired-baseline.json`.
 *      - Explicitly verifies zero cycles between `composite-receipt.ts` and `terminal-oracle-registry.ts`.
 *   2. Unwired / test-only value export ratchet over `src/server/**`:
 *      - Finds declared value exports in `src/server/**` with zero external non-test callers
 *        (resolving direct imports and transitive re-exports across `src/`, `scripts/`, `worker/`).
 *      - Allows explicit `keep-unwired` entries with a measured-gate ticket + reason so
 *        precision-sensitive primitives (e.g. signed-scope enforcement, composite patch retest)
 *        are never rushed live.
 *      - Fails on any NEW un-baselined / un-annotated unwired value export.
 *   3. `ARCHITECTURE.md` stale-symbol gate:
 *      - Fails if `ARCHITECTURE.md` cites a `src/server/**` value export as live when it has
 *        zero external non-test callers (unless the citing paragraph/node explicitly documents
 *        it as pending wiring / unit-tested only).
 *
 * Usage:
 *   node scripts/check-unwired.ts                   # enforce ratchet (exit 0 PASS / exit 1 FAIL)
 *   node scripts/check-unwired.ts --json            # print machine-readable JSON summary
 *   node scripts/check-unwired.ts --write-baseline  # refresh scripts/unwired-baseline.json
 */
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, posix, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import ts from 'typescript'

export interface KeepUnwiredEntry {
  key: string
  disposition: 'keep-unwired'
  ticket: string
  reason: string
}

export interface UnwiredBaseline {
  version: 1
  allowedCycles: string[]
  keepUnwired: KeepUnwiredEntry[]
  baselinedExports: string[]
}

export interface UnwiredExportFinding {
  key: string
  file: string
  symbol: string
  kind: 'test_only' | 'unreferenced'
  usedInternallyInModule: boolean
  testImporters: string[]
}

export interface StaleDocCitation {
  file: string
  line: number
  symbol: string
  declaringFiles: string[]
  excerpt: string
}

export interface UnwiredCheckResult {
  ok: boolean
  rootDir: string
  filesScanned: number
  cycles: string[]
  newCycles: string[]
  fixedCycles: string[]
  proofKernelCyclePresent: boolean
  totalServerValueExports: number
  wiredExportCount: number
  unwiredExports: UnwiredExportFinding[]
  newUnwiredExports: UnwiredExportFinding[]
  resolvedBaselineExports: string[]
  invalidKeepUnwired: string[]
  staleDocCitations: StaleDocCitation[]
  durationMs: number
}

const EXCLUDED_DIRS = new Set(['node_modules', '.git', 'dist', '.output', '.nitro', '.vinxi', '.tanstack', 'coverage'])
const TEST_FILE_RE = /(?:^|\/)(?:tests?|__tests__)\/|(?:\.test|\.spec)\.[^./\\]+$/i
const TS_EXT_RE = /\.(?:ts|tsx|mts|cts)$/i

/**
 * Known precision-sensitive / gate-tracked unwired primitives preserved across baseline refreshes.
 * These MUST NEVER be rushed live without their measured-gate ticket.
 */
export const DEFAULT_KEEP_UNWIRED: readonly KeepUnwiredEntry[] = [
  {
    key: 'src/server/scope-policy.ts::signScopeManifest',
    disposition: 'keep-unwired',
    ticket: 'MEASURED-GATE-SIGNED-SCOPE',
    reason: 'Precision-sensitive signed-scope manifest signing; keep unwired until measured-gate ticket lands.',
  },
  {
    key: 'src/server/scope-policy.ts::evaluateSignedScopeRequest',
    disposition: 'keep-unwired',
    ticket: 'MEASURED-GATE-SIGNED-SCOPE',
    reason: 'Precision-sensitive signed-scope request enforcement; keep unwired until measured-gate ticket lands.',
  },
  {
    key: 'src/server/patch-workflow.ts::retestCompositeChainPatch',
    disposition: 'keep-unwired',
    ticket: 'GATE-6-Q8-COMPOSITE-PATCH-RETEST',
    reason: 'Multi-hop composite chain patch retest is unit-tested and pending production Gate-6 wiring in Q8.',
  },
  {
    key: 'src/server/patch-workflow.ts::computeCompositeRetestProofDigest',
    disposition: 'keep-unwired',
    ticket: 'GATE-6-Q8-COMPOSITE-PATCH-RETEST',
    reason: 'Proof digest helper for retestCompositeChainPatch; pending production Gate-6 wiring in Q8.',
  },
  {
    key: 'src/server/patch-workflow.ts::verifyCompositeRetestProofDigest',
    disposition: 'keep-unwired',
    ticket: 'GATE-6-Q8-COMPOSITE-PATCH-RETEST',
    reason: 'Digest verifier for retestCompositeChainPatch; pending production Gate-6 wiring in Q8.',
  },
]

function toPosix(p: string): string {
  return sep === '/' ? p : p.split(sep).join(posix.sep)
}

function toRelPosix(rootDir: string, absPath: string): string {
  return toPosix(relative(rootDir, absPath))
}

function collectTsFiles(rootDir: string, relDirs: readonly string[]): string[] {
  const out: string[] = []
  const walk = (absDir: string) => {
    if (!existsSync(absDir)) return
    const entries = readdirSync(absDir, { withFileTypes: true })
    entries.sort((a, b) => a.name.localeCompare(b.name))
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue
      const full = join(absDir, entry.name)
      if (entry.isDirectory()) {
        if (EXCLUDED_DIRS.has(entry.name)) continue
        walk(full)
      } else if (entry.isFile() && TS_EXT_RE.test(entry.name) && !entry.name.endsWith('.d.ts')) {
        out.push(toRelPosix(rootDir, full))
      }
    }
  }
  for (const rel of relDirs) {
    const abs = join(rootDir, rel)
    if (!existsSync(abs)) continue
    const st = statSync(abs)
    if (st.isFile()) out.push(toRelPosix(rootDir, abs))
    else if (st.isDirectory()) walk(abs)
  }
  return out
}

function resolveLocalSpecifier(rootDir: string, fromRel: string, spec: string): string | null {
  if (!spec.startsWith('.')) return null
  const baseAbs = resolve(rootDir, dirname(fromRel), spec)
  const candidates = [
    baseAbs,
    `${baseAbs}.ts`,
    `${baseAbs}.tsx`,
    `${baseAbs}.mts`,
    join(baseAbs, 'index.ts'),
    join(baseAbs, 'index.tsx'),
  ]
  if (spec.endsWith('.js') || spec.endsWith('.jsx')) {
    const stem = baseAbs.slice(0, -3)
    candidates.unshift(`${stem}.ts`, `${stem}.tsx`)
  }
  for (const cand of candidates) {
    if (existsSync(cand) && statSync(cand).isFile()) {
      return toRelPosix(rootDir, cand)
    }
  }
  return null
}

function hasExportModifier(node: ts.Node): boolean {
  const mods = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined
  return Boolean(mods?.some(m => m.kind === ts.SyntaxKind.ExportKeyword))
}

function hasDefaultModifier(node: ts.Node): boolean {
  const mods = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined
  return Boolean(mods?.some(m => m.kind === ts.SyntaxKind.DefaultKeyword))
}

interface ParsedFileInfo {
  relPath: string
  isTest: boolean
  isEntrypoint: boolean
  /** Runtime (value-level) module dependencies (for cycle detection). */
  runtimeDeps: Set<string>
  /** Value symbols declared and exported directly by this file. */
  declaredValueExports: Set<string>
  /** Local value identifiers declared in this file (used to distinguish local exports vs re-exports). */
  localValueDecls: Set<string>
  /** Named imports: localName -> { from, importedName } (non-type-only). */
  namedImports: Map<string, { from: string; importedName: string }>
  /** Namespace imports: localName -> from (non-type-only). */
  namespaceImports: Map<string, string>
  /** Direct re-exports: exportedName -> { from, importedName }. */
  reexports: Map<string, { from: string; importedName: string }>
  /** Star re-exports: target files. */
  starReexports: Set<string>
  /** Side-effect imports (`import './x.ts'`). */
  sideEffectImports: Set<string>
  /** Exported local aliases (`export { local as exported }` without `from`). */
  localExportAliases: Map<string, string>
  /** Identifiers referenced in non-import / non-export-specifier executable code. */
  usedIdentifiers: Set<string>
  /** Declared value exports referenced by a DIFFERENT top-level statement in the same file. */
  sameFileCallers: Set<string>
  /** Property accesses on namespace imports: nsLocalName -> Set<propName>. */
  namespaceProps: Map<string, Set<string>>
  /** Namespace imports used as whole values (e.g. passed to a function, spread, etc.). */
  wholeNamespacesUsed: Set<string>
}

function isProductionEntrypoint(relPath: string): boolean {
  if (TEST_FILE_RE.test(relPath)) return false
  return (
    relPath === 'src/server.ts'
    || relPath === 'src/actions.ts'
    || relPath.startsWith('src/routes/')
    || relPath.startsWith('scripts/')
    || relPath.startsWith('worker/')
  )
}

function collectBindingNames(name: ts.BindingName, out: Set<string>): void {
  if (ts.isIdentifier(name)) {
    out.add(name.text)
    return
  }
  for (const el of name.elements) {
    if (ts.isBindingElement(el)) collectBindingNames(el.name, out)
  }
}

function parseFileInfo(rootDir: string, relPath: string): ParsedFileInfo {
  const full = join(rootDir, relPath)
  const text = readFileSync(full, 'utf8')
  const kind = relPath.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
  const sf = ts.createSourceFile(relPath, text, ts.ScriptTarget.Latest, true, kind)

  const info: ParsedFileInfo = {
    relPath,
    isTest: TEST_FILE_RE.test(relPath),
    isEntrypoint: isProductionEntrypoint(relPath),
    runtimeDeps: new Set(),
    declaredValueExports: new Set(),
    localValueDecls: new Set(),
    namedImports: new Map(),
    namespaceImports: new Map(),
    reexports: new Map(),
    starReexports: new Set(),
    sideEffectImports: new Set(),
    localExportAliases: new Map(),
    usedIdentifiers: new Set(),
    sameFileCallers: new Set(),
    namespaceProps: new Map(),
    wholeNamespacesUsed: new Set(),
  }

  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      const target = resolveLocalSpecifier(rootDir, relPath, stmt.moduleSpecifier.text)
      if (!target) continue
      const ic = stmt.importClause
      if (!ic) {
        info.runtimeDeps.add(target)
        info.sideEffectImports.add(target)
        continue
      }
      if (ic.isTypeOnly) continue
      let hasRuntime = false
      if (ic.name) {
        hasRuntime = true
        info.namedImports.set(ic.name.text, { from: target, importedName: 'default' })
      }
      if (ic.namedBindings) {
        if (ts.isNamespaceImport(ic.namedBindings)) {
          hasRuntime = true
          info.namespaceImports.set(ic.namedBindings.name.text, target)
        } else {
          for (const el of ic.namedBindings.elements) {
            if (el.isTypeOnly) continue
            hasRuntime = true
            const importedName = el.propertyName ? el.propertyName.text : el.name.text
            info.namedImports.set(el.name.text, { from: target, importedName })
          }
        }
      }
      if (hasRuntime) info.runtimeDeps.add(target)
      continue
    }

    if (ts.isExportDeclaration(stmt)) {
      if (stmt.isTypeOnly) continue
      if (stmt.moduleSpecifier && ts.isStringLiteral(stmt.moduleSpecifier)) {
        const target = resolveLocalSpecifier(rootDir, relPath, stmt.moduleSpecifier.text)
        if (!target) continue
        if (!stmt.exportClause) {
          info.runtimeDeps.add(target)
          info.starReexports.add(target)
        } else if (ts.isNamespaceExport(stmt.exportClause)) {
          info.runtimeDeps.add(target)
          info.declaredValueExports.add(stmt.exportClause.name.text)
          info.starReexports.add(target)
        } else {
          let hasRuntime = false
          for (const el of stmt.exportClause.elements) {
            if (el.isTypeOnly) continue
            hasRuntime = true
            const importedName = el.propertyName ? el.propertyName.text : el.name.text
            info.reexports.set(el.name.text, { from: target, importedName })
          }
          if (hasRuntime) info.runtimeDeps.add(target)
        }
      } else if (stmt.exportClause && ts.isNamedExports(stmt.exportClause)) {
        for (const el of stmt.exportClause.elements) {
          if (el.isTypeOnly) continue
          const localName = el.propertyName ? el.propertyName.text : el.name.text
          const exportedName = el.name.text
          info.localExportAliases.set(exportedName, localName)
        }
      }
      continue
    }

    if (ts.isExportAssignment(stmt) && !stmt.isExportEquals) {
      info.declaredValueExports.add('default')
      continue
    }

    const exported = hasExportModifier(stmt)
    const isDefault = hasDefaultModifier(stmt)
    if (ts.isFunctionDeclaration(stmt) && stmt.body) {
      if (stmt.name) {
        info.localValueDecls.add(stmt.name.text)
        if (exported) info.declaredValueExports.add(isDefault ? 'default' : stmt.name.text)
      } else if (exported && isDefault) {
        info.declaredValueExports.add('default')
      }
    } else if (ts.isClassDeclaration(stmt)) {
      if (stmt.name) {
        info.localValueDecls.add(stmt.name.text)
        if (exported) info.declaredValueExports.add(isDefault ? 'default' : stmt.name.text)
      } else if (exported && isDefault) {
        info.declaredValueExports.add('default')
      }
    } else if (ts.isEnumDeclaration(stmt)) {
      info.localValueDecls.add(stmt.name.text)
      if (exported) info.declaredValueExports.add(stmt.name.text)
    } else if (ts.isVariableStatement(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        const names = new Set<string>()
        collectBindingNames(decl.name, names)
        for (const n of names) {
          info.localValueDecls.add(n)
          if (exported) info.declaredValueExports.add(n)
        }
      }
    }
  }

  // Resolve `export { local as exported }` (without `from`):
  // if `local` was imported from another module, treat as a re-export; otherwise if declared locally, a declared value export.
  for (const [exportedName, localName] of info.localExportAliases) {
    const imp = info.namedImports.get(localName)
    if (imp) {
      info.reexports.set(exportedName, imp)
    } else if (info.localValueDecls.has(localName)) {
      info.declaredValueExports.add(exportedName)
    }
  }

  // Collect identifier references outside import/export declarations so we distinguish
  // real runtime usages from pure barrel re-exports, and track cross-statement same-file callers.
  const stmtDeclaredNames = (stmt: ts.Statement): Set<string> => {
    const names = new Set<string>()
    if ((ts.isFunctionDeclaration(stmt) || ts.isClassDeclaration(stmt) || ts.isEnumDeclaration(stmt)) && stmt.name) {
      names.add(stmt.name.text)
    } else if (ts.isVariableStatement(stmt)) {
      for (const decl of stmt.declarationList.declarations) collectBindingNames(decl.name, names)
    }
    return names
  }

  for (const stmt of sf.statements) {
    const ownNames = stmtDeclaredNames(stmt)
    const stmtRefs = new Set<string>()
    const walkUsage = (node: ts.Node) => {
      if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) return
      if (ts.isHeritageClause(node)) {
        if (node.token === ts.SyntaxKind.ExtendsKeyword) {
          for (const t of node.types) walkUsage(t.expression)
        }
        return
      }
      if (ts.isTypeNode(node) && !ts.isTypeQueryNode(node)) return
      if (ts.isInterfaceDeclaration(node) || ts.isTypeAliasDeclaration(node)) return
      if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression) && info.namespaceImports.has(node.expression.text)) {
        const ns = node.expression.text
        let set = info.namespaceProps.get(ns)
        if (!set) { set = new Set(); info.namespaceProps.set(ns, set) }
        set.add(node.name.text)
        return
      }
      if (ts.isIdentifier(node)) {
        const parent = node.parent
        // Skip property names in `{ foo: 1 }` and `obj.foo`
        if (ts.isPropertyAccessExpression(parent) && parent.name === node) return
        if (ts.isPropertyAssignment(parent) && parent.name === node) return
        if (ts.isMethodDeclaration(parent) && parent.name === node) return
        if (ts.isParameter(parent) && parent.name === node) return
        if (ts.isVariableDeclaration(parent) && parent.name === node) return
        if ((ts.isFunctionDeclaration(parent) || ts.isClassDeclaration(parent) || ts.isEnumDeclaration(parent)) && parent.name === node) return
        info.usedIdentifiers.add(node.text)
        stmtRefs.add(node.text)
        if (info.namespaceImports.has(node.text)) {
          info.wholeNamespacesUsed.add(node.text)
        }
      }
      ts.forEachChild(node, walkUsage)
    }
    walkUsage(stmt)
    for (const ref of stmtRefs) {
      if (!ownNames.has(ref) && info.declaredValueExports.has(ref)) {
        info.sameFileCallers.add(ref)
      }
    }
  }

  return info
}

/**
 * Find all elementary runtime import cycles in `src/**` (canonicalized by rotating each cycle
 * to its lexicographically smallest file path).
 */
export function findRuntimeImportCycles(files: Map<string, ParsedFileInfo>): string[] {
  const srcNodes = [...files.keys()].filter(k => k.startsWith('src/') && !TEST_FILE_RE.test(k)).sort()
  const srcSet = new Set(srcNodes)

  // Tarjan's SCC to isolate cyclic components cleanly.
  let counter = 0
  const index = new Map<string, number>()
  const lowlink = new Map<string, number>()
  const stack: string[] = []
  const onStack = new Set<string>()
  const sccs: string[][] = []

  const strongconnect = (v: string) => {
    index.set(v, counter)
    lowlink.set(v, counter)
    counter += 1
    stack.push(v)
    onStack.add(v)
    const deps = [...(files.get(v)?.runtimeDeps ?? [])].filter(d => srcSet.has(d)).sort()
    for (const w of deps) {
      if (!index.has(w)) {
        strongconnect(w)
        lowlink.set(v, Math.min(lowlink.get(v)!, lowlink.get(w)!))
      } else if (onStack.has(w)) {
        lowlink.set(v, Math.min(lowlink.get(v)!, index.get(w)!))
      }
    }
    if (lowlink.get(v) === index.get(v)) {
      const comp: string[] = []
      while (true) {
        const w = stack.pop()!
        onStack.delete(w)
        comp.push(w)
        if (w === v) break
      }
      if (comp.length > 1) {
        sccs.push(comp.sort())
      } else if (comp.length === 1 && files.get(comp[0]!)?.runtimeDeps.has(comp[0]!)) {
        sccs.push(comp)
      }
    }
  }
  for (const node of srcNodes) {
    if (!index.has(node)) strongconnect(node)
  }

  // Enumerate canonical elementary cycles inside each SCC.
  const canonicalCycles = new Set<string>()
  for (const comp of sccs) {
    const compSet = new Set(comp)
    for (const start of comp) {
      const path: string[] = [start]
      const visited = new Set<string>([start])
      const dfs = (curr: string) => {
        if (canonicalCycles.size > 200) return
        const deps = [...(files.get(curr)?.runtimeDeps ?? [])]
          .filter(d => compSet.has(d) && d >= start)
          .sort()
        for (const next of deps) {
          if (next === start) {
            canonicalCycles.add([...path, start].join(' -> '))
          } else if (!visited.has(next)) {
            visited.add(next)
            path.push(next)
            dfs(next)
            path.pop()
            visited.delete(next)
          }
        }
      }
      dfs(start)
    }
  }
  return [...canonicalCycles].sort()
}

function analyzeUnwiredExports(files: Map<string, ParsedFileInfo>): {
  totalServerValueExports: number
  wiredKeys: Set<string>
  liveDocKeys: Set<string>
  unwired: UnwiredExportFinding[]
  declaredBySymbol: Map<string, string[]>
} {
  // Build reverse index: for every (file, exportName), trace whether any non-test caller uses it,
  // propagating backward through re-exports (`export { a as b } from './x'`, `export * from './x'`).
  const prodUsed = new Set<string>() // key: `${file}::${exportName}`
  const queue: Array<{ file: string; name: string }> = []

  const markProdUsed = (file: string, name: string) => {
    const key = `${file}::${name}`
    if (prodUsed.has(key)) return
    prodUsed.add(key)
    queue.push({ file, name })
  }

  const markAllExportsProdUsed = (file: string) => {
    const info = files.get(file)
    if (!info) return
    for (const exp of info.declaredValueExports) markProdUsed(file, exp)
    for (const exp of info.reexports.keys()) markProdUsed(file, exp)
    for (const starTarget of info.starReexports) markAllExportsProdUsed(starTarget)
  }

  // Seed prodUsed from every non-test file's real usages (and entrypoint exports).
  for (const info of files.values()) {
    if (info.isTest) continue
    for (const [localName, imp] of info.namedImports) {
      if (info.usedIdentifiers.has(localName)) {
        markProdUsed(imp.from, imp.importedName)
      }
    }
    for (const [nsLocal, target] of info.namespaceImports) {
      if (info.wholeNamespacesUsed.has(nsLocal)) {
        markAllExportsProdUsed(target)
      } else {
        for (const prop of info.namespaceProps.get(nsLocal) ?? []) {
          markProdUsed(target, prop)
        }
      }
    }
    if (info.isEntrypoint) {
      for (const [exp, target] of info.reexports) {
        markProdUsed(info.relPath, exp)
        markProdUsed(target.from, target.importedName)
      }
      for (const starTarget of info.starReexports) {
        markAllExportsProdUsed(starTarget)
      }
    }
  }

  // Propagate backward across re-export chains.
  while (queue.length > 0) {
    const { file, name } = queue.shift()!
    const info = files.get(file)
    if (!info) continue
    const reexp = info.reexports.get(name)
    if (reexp) {
      markProdUsed(reexp.from, reexp.importedName)
    }
    if (!info.declaredValueExports.has(name) && !reexp && info.starReexports.size > 0) {
      for (const starTarget of info.starReexports) {
        markProdUsed(starTarget, name)
      }
    }
  }

  // Collect test importers (also resolving through re-exports).
  const testImportersByKey = new Map<string, Set<string>>()
  const recordTestUse = (file: string, name: string, testFile: string, seen = new Set<string>()) => {
    const key = `${file}::${name}`
    if (seen.has(key)) return
    seen.add(key)
    let set = testImportersByKey.get(key)
    if (!set) { set = new Set(); testImportersByKey.set(key, set) }
    set.add(testFile)
    const info = files.get(file)
    if (!info) return
    const reexp = info.reexports.get(name)
    if (reexp) recordTestUse(reexp.from, reexp.importedName, testFile, seen)
    if (!info.declaredValueExports.has(name) && !reexp) {
      for (const starTarget of info.starReexports) {
        recordTestUse(starTarget, name, testFile, seen)
      }
    }
  }

  for (const info of files.values()) {
    if (!info.isTest) continue
    for (const [, imp] of info.namedImports) {
      recordTestUse(imp.from, imp.importedName, info.relPath)
    }
    for (const [nsLocal, target] of info.namespaceImports) {
      const targetInfo = files.get(target)
      if (!targetInfo) continue
      if (info.wholeNamespacesUsed.has(nsLocal)) {
        for (const exp of targetInfo.declaredValueExports) recordTestUse(target, exp, info.relPath)
      } else {
        for (const prop of info.namespaceProps.get(nsLocal) ?? []) recordTestUse(target, prop, info.relPath)
      }
    }
  }

  const wiredKeys = new Set<string>()
  const liveDocKeys = new Set<string>()
  const unwired: UnwiredExportFinding[] = []
  const declaredBySymbol = new Map<string, string[]>()
  let totalServerValueExports = 0

  const serverFiles = [...files.values()]
    .filter(f => f.relPath.startsWith('src/server/') && !f.isTest)
    .sort((a, b) => a.relPath.localeCompare(b.relPath))

  for (const info of serverFiles) {
    const moduleHasProdConsumer = [...info.declaredValueExports].some(exp => prodUsed.has(`${info.relPath}::${exp}`))
      || [...info.reexports.keys()].some(exp => prodUsed.has(`${info.relPath}::${exp}`))
    for (const sym of [...info.declaredValueExports].sort()) {
      totalServerValueExports += 1
      const key = `${info.relPath}::${sym}`
      const existing = declaredBySymbol.get(sym) ?? []
      existing.push(info.relPath)
      declaredBySymbol.set(sym, existing)

      const usedInternallyInModule = moduleHasProdConsumer && info.sameFileCallers.has(sym)
      if (prodUsed.has(key)) {
        wiredKeys.add(key)
        liveDocKeys.add(key)
      } else {
        if (usedInternallyInModule) liveDocKeys.add(key)
        const testImporters = [...(testImportersByKey.get(key) ?? [])].sort()
        unwired.push({
          key,
          file: info.relPath,
          symbol: sym,
          kind: testImporters.length > 0 ? 'test_only' : 'unreferenced',
          usedInternallyInModule,
          testImporters,
        })
      }
    }
  }

  return { totalServerValueExports, wiredKeys, liveDocKeys, unwired, declaredBySymbol }
}

const PENDING_DOC_QUALIFIER_RE =
  /\b(?:pending\b[^.\n]*\bwiring|not\s+yet\s+(?:wired|invoked)|unwired|unit-tested\s+only|being\s+retired|retiring)\b/i

/**
 * Scan `ARCHITECTURE.md` for cited `src/server/**` value exports that have ZERO non-test callers
 * and are not explicitly documented as pending/unwired.
 */
export function scanArchitectureDocCitations(
  rootDir: string,
  declaredBySymbol: Map<string, string[]>,
  wiredKeys: Set<string>,
  docRelPath = 'ARCHITECTURE.md',
): StaleDocCitation[] {
  const fullPath = join(rootDir, docRelPath)
  if (!existsSync(fullPath)) return []
  const content = readFileSync(fullPath, 'utf8')
  const lines = content.split(/\r?\n/)

  // Compute paragraph-level context for each line (blank lines or headings/table rows delimit blocks).
  const paragraphOfLine = new Array<string>(lines.length).fill('')
  let blockStart = 0
  const flushBlock = (end: number) => {
    const joined = lines.slice(blockStart, end).join(' ')
    for (let i = blockStart; i < end; i += 1) paragraphOfLine[i] = joined
  }
  for (let i = 0; i < lines.length; i += 1) {
    const trimmed = lines[i]!.trim()
    if (!trimmed || trimmed.startsWith('|') || trimmed.startsWith('```') || trimmed.startsWith('#')) {
      flushBlock(i)
      paragraphOfLine[i] = lines[i]!
      blockStart = i + 1
    }
  }
  flushBlock(lines.length)

  const stale: StaleDocCitation[] = []
  const seen = new Set<string>()
  const backtickRe = /`([A-Za-z_$][A-Za-z0-9_$]*)(?:\(\))?`/g
  const mermaidIdentRe = /\b([a-z][A-Za-z0-9]{5,}|[A-Z][a-z]+[A-Z][A-Za-z0-9]+)\b/g
  let inMermaid = false

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]!
    if (/^\s*```mermaid\b/.test(line)) { inMermaid = true; continue }
    if (inMermaid && /^\s*```/.test(line)) { inMermaid = false; continue }

    const candidates = new Set<string>()
    for (const m of line.matchAll(backtickRe)) candidates.add(m[1]!)
    if (inMermaid) {
      for (const m of line.matchAll(mermaidIdentRe)) candidates.add(m[1]!)
    }

    const contextText = inMermaid ? line : paragraphOfLine[i]!
    if (PENDING_DOC_QUALIFIER_RE.test(contextText)) continue

    for (const sym of candidates) {
      const declaringFiles = declaredBySymbol.get(sym)
      if (!declaringFiles || declaringFiles.length === 0) continue
      const anyWired = declaringFiles.some(f => wiredKeys.has(`${f}::${sym}`))
      if (anyWired) continue
      const dedupeKey = `${i + 1}:${sym}`
      if (seen.has(dedupeKey)) continue
      seen.add(dedupeKey)
      stale.push({
        file: docRelPath,
        line: i + 1,
        symbol: sym,
        declaringFiles: [...declaringFiles].sort(),
        excerpt: line.trim().slice(0, 140),
      })
    }
  }
  return stale
}

export function loadUnwiredBaseline(baselinePath: string): UnwiredBaseline {
  if (!existsSync(baselinePath)) {
    return {
      version: 1,
      allowedCycles: [],
      keepUnwired: [...DEFAULT_KEEP_UNWIRED],
      baselinedExports: [],
    }
  }
  return JSON.parse(readFileSync(baselinePath, 'utf8')) as UnwiredBaseline
}

export function runUnwiredCheck(options: {
  rootDir?: string
  baselinePath?: string
  baseline?: UnwiredBaseline
  docRelPath?: string
} = {}): UnwiredCheckResult {
  const started = Date.now()
  const rootDir = resolve(options.rootDir ?? join(dirname(fileURLToPath(import.meta.url)), '..'))
  const baselinePath = options.baselinePath ?? join(rootDir, 'scripts/unwired-baseline.json')
  const baseline = options.baseline ?? loadUnwiredBaseline(baselinePath)

  const relFiles = collectTsFiles(rootDir, ['src', 'scripts', 'worker', 'tests'])
  const parsedFiles = new Map<string, ParsedFileInfo>()
  for (const rel of relFiles) {
    parsedFiles.set(rel, parseFileInfo(rootDir, rel))
  }

  // 1. Runtime import cycles
  const cycles = findRuntimeImportCycles(parsedFiles)
  const allowedCycleSet = new Set(baseline.allowedCycles)
  const newCycles = cycles.filter(c => !allowedCycleSet.has(c))
  const fixedCycles = baseline.allowedCycles.filter(c => !cycles.includes(c))
  const proofKernelCyclePresent = cycles.some(
    c => c.includes('src/server/composite-receipt.ts') && c.includes('src/server/terminal-oracle-registry.ts'),
  )

  // 2. Unwired / test-only value exports
  const { totalServerValueExports, wiredKeys, liveDocKeys, unwired, declaredBySymbol } = analyzeUnwiredExports(parsedFiles)
  const invalidKeepUnwired: string[] = []
  const keepSet = new Set<string>()
  for (const entry of baseline.keepUnwired) {
    if (entry.disposition !== 'keep-unwired' || !entry.ticket?.trim() || !entry.reason?.trim()) {
      invalidKeepUnwired.push(entry.key)
    } else {
      keepSet.add(entry.key)
    }
  }
  const baselinedSet = new Set(baseline.baselinedExports)
  const unwiredKeySet = new Set(unwired.map(u => u.key))

  const newUnwiredExports = unwired.filter(u => !keepSet.has(u.key) && !baselinedSet.has(u.key))
  const resolvedBaselineExports = baseline.baselinedExports.filter(k => !unwiredKeySet.has(k))

  // 3. ARCHITECTURE.md stale citations
  const staleDocCitations = scanArchitectureDocCitations(
    rootDir,
    declaredBySymbol,
    liveDocKeys,
    options.docRelPath ?? 'ARCHITECTURE.md',
  )

  const ok =
    !proofKernelCyclePresent
    && newCycles.length === 0
    && newUnwiredExports.length === 0
    && invalidKeepUnwired.length === 0
    && staleDocCitations.length === 0

  return {
    ok,
    rootDir,
    filesScanned: parsedFiles.size,
    cycles,
    newCycles,
    fixedCycles,
    proofKernelCyclePresent,
    totalServerValueExports,
    wiredExportCount: wiredKeys.size,
    unwiredExports: unwired,
    newUnwiredExports,
    resolvedBaselineExports,
    invalidKeepUnwired,
    staleDocCitations,
    durationMs: Date.now() - started,
  }
}

export function buildBaselineFromResult(
  result: UnwiredCheckResult,
  existingKeepUnwired: readonly KeepUnwiredEntry[] = DEFAULT_KEEP_UNWIRED,
): UnwiredBaseline {
  const unwiredKeys = new Set(result.unwiredExports.map(u => u.key))
  const keepUnwired = existingKeepUnwired
    .filter(e => unwiredKeys.has(e.key))
    .sort((a, b) => a.key.localeCompare(b.key))
  const keepSet = new Set(keepUnwired.map(e => e.key))
  const baselinedExports = result.unwiredExports
    .map(u => u.key)
    .filter(k => !keepSet.has(k))
    .sort()
  return {
    version: 1,
    allowedCycles: [...result.cycles].sort(),
    keepUnwired,
    baselinedExports,
  }
}

function main(): void {
  const args = new Set(process.argv.slice(2))
  const rootDir = resolve(join(dirname(fileURLToPath(import.meta.url)), '..'))
  const baselinePath = join(rootDir, 'scripts/unwired-baseline.json')

  if (args.has('--write-baseline')) {
    const existing = existsSync(baselinePath) ? loadUnwiredBaseline(baselinePath) : null
    const mergedKeep = existing?.keepUnwired?.length ? existing.keepUnwired : DEFAULT_KEEP_UNWIRED
    const scan = runUnwiredCheck({ rootDir, baseline: { version: 1, allowedCycles: [], keepUnwired: [...mergedKeep], baselinedExports: [] } })
    const nextBaseline = buildBaselineFromResult(scan, mergedKeep)
    writeFileSync(baselinePath, `${JSON.stringify(nextBaseline, null, 2)}\n`, 'utf8')
    console.log(
      `wrote ${relative(rootDir, baselinePath)}: cycles=${nextBaseline.allowedCycles.length}, `
      + `keepUnwired=${nextBaseline.keepUnwired.length}, baselinedExports=${nextBaseline.baselinedExports.length}`,
    )
    return
  }

  const res = runUnwiredCheck({ rootDir, baselinePath })
  if (args.has('--json')) {
    console.log(JSON.stringify(res, null, 2))
    process.exit(res.ok ? 0 : 1)
  }

  console.log(
    `check-unwired: ${res.ok ? 'PASS' : 'FAIL'} `
    + `(files=${res.filesScanned}, cycles=${res.cycles.length}, newCycles=${res.newCycles.length}, `
    + `serverExports=${res.totalServerValueExports}, wired=${res.wiredExportCount}, `
    + `unwired=${res.unwiredExports.length}, newUnwired=${res.newUnwiredExports.length}, `
    + `staleDocCitations=${res.staleDocCitations.length}, ${res.durationMs}ms)`,
  )

  if (res.proofKernelCyclePresent) {
    console.error('FAIL: proof-kernel cycle detected between composite-receipt.ts and terminal-oracle-registry.ts!')
  }
  for (const cyc of res.newCycles) {
    console.error(`FAIL [new-cycle]: ${cyc}`)
  }
  for (const inv of res.invalidKeepUnwired) {
    console.error(`FAIL [invalid-keep-unwired]: ${inv} requires disposition="keep-unwired", ticket, and reason`)
  }
  for (const exp of res.newUnwiredExports) {
    console.error(`FAIL [new-unwired-export]: ${exp.key} (${exp.kind}; tests=[${exp.testImporters.slice(0, 3).join(', ')}])`)
  }
  for (const cite of res.staleDocCitations) {
    console.error(`FAIL [stale-architecture-doc]: ${cite.file}:${cite.line} cites unwired symbol "${cite.symbol}" (${cite.declaringFiles.join(', ')})`)
  }
  if (res.fixedCycles.length > 0) {
    console.log(`NOTE: ${res.fixedCycles.length} baselined cycle(s) resolved and can be removed from scripts/unwired-baseline.json.`)
  }
  if (res.resolvedBaselineExports.length > 0) {
    console.log(`NOTE: ${res.resolvedBaselineExports.length} baselined unwired export(s) are now wired/deleted and can be pruned from scripts/unwired-baseline.json.`)
  }
  process.exit(res.ok ? 0 : 1)
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main()
}
