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
 *      - Drops own-module-only noise (`usedInternallyInModule: true`, i.e. exports called internally
 *        by a production-consumed module) from the unwired metric so only true cross-module dead
 *        primitives are counted.
 *      - Allows explicit `keep-unwired` entries with a measured-gate ticket + reason so
 *        precision-sensitive primitives (e.g. signed-scope enforcement) are never rushed live,
 *        and flags stale `keep-unwired` entries once wired internally/externally or deleted.
 *      - Fails on any NEW un-baselined / un-annotated unwired value export AND prune-fails on
 *        `resolvedBaselineExports > 0` until stale baseline entries are pruned.
 *      - `--write-baseline` is **removal-only** by default (monotone ratchet): refuses to add new
 *        entries unless `--allow-add-with-ticket` supplies per-entry `{ owner, ticket, expires }`.
 *   3. `ARCHITECTURE.md` stale-symbol gate:
 *      - Fails if `ARCHITECTURE.md` cites a `src/server/**` value export as live when it has
 *        zero external non-test callers (unless the citing paragraph/node explicitly documents
 *        it as pending wiring / unit-tested only).
 *
 * Usage:
 *   node scripts/check-unwired.ts                   # enforce ratchet (exit 0 PASS / exit 1 FAIL)
 *   node scripts/check-unwired.ts --json            # print machine-readable JSON summary
 *   node scripts/check-unwired.ts --write-baseline  # removal-only prune of scripts/unwired-baseline.json
 *   node scripts/check-unwired.ts --write-baseline --allow-add-with-ticket --owner <o> --ticket <t> --expires <YYYY-MM-DD>
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

export interface TicketedBaselineAddition {
  key: string
  owner: string
  ticket: string
  expires: string
}

export interface StaleKeepUnwiredEntry {
  key: string
  status: 'wired_externally' | 'wired_internally' | 'deleted'
}

export interface UnwiredBaseline {
  version: 1
  allowedCycles: string[]
  keepUnwired: KeepUnwiredEntry[]
  baselinedExports: string[]
  ticketedAdditions?: TicketedBaselineAddition[]
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

export interface ReachabilitySummary {
  /** Number of declared production entrypoint files seeded for the reachability walk. */
  entrypoints: number
  /** Server value exports reachable via value references from declared production entrypoints. */
  reachable: number
  /** Server value exports unreachable from production entrypoints, imported only by tests. */
  testOnly: number
  /** Server value exports unreachable from both production entrypoints and tests. */
  unreachable: number
  /** Sorted keys (`<file>::<symbol>`) classified as test-only by the reachability walk. */
  testOnlyKeys: string[]
  /** Sorted keys (`<file>::<symbol>`) classified as unreachable by the reachability walk. */
  unreachableKeys: string[]
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
  ownModuleOnlyExportCount: number
  unwiredExports: UnwiredExportFinding[]
  newUnwiredExports: UnwiredExportFinding[]
  resolvedBaselineExports: string[]
  invalidKeepUnwired: string[]
  staleKeepUnwired: StaleKeepUnwiredEntry[]
  invalidTicketedAdditions: string[]
  staleDocCitations: StaleDocCitation[]
  /** Production-entrypoint value-reference reachability walk summary (R3-09; warn-only during rollout). */
  reachability: ReachabilitySummary
  durationMs: number
}

const EXCLUDED_DIRS = new Set(['node_modules', '.git', 'dist', '.output', '.nitro', '.vinxi', '.tanstack', 'coverage'])
const TEST_FILE_RE = /(?:^|\/)(?:tests?|__tests__)\/|(?:\.test|\.spec)\.[^./\\]+$/i
const TS_EXT_RE = /\.(?:ts|tsx|mts|cts)$/i
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/

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
  /** Per-symbol value references inside its declaring top-level statement (for reachability BFS). */
  symbolInternalRefs: Map<string, Set<string>>
  /** Identifiers referenced by eager top-level module-init statements (run on module load). */
  moduleInitRefs: Set<string>
  /** Namespace re-exports (`export * as ns from './x'`): exportedNsName -> targetFile. */
  namespaceReexports: Map<string, string>
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

function isReachabilityEntrypoint(relPath: string): boolean {
  if (TEST_FILE_RE.test(relPath)) return false
  return (
    isProductionEntrypoint(relPath)
    || relPath === 'src/router.tsx'
    || relPath === 'src/client.tsx'
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
    symbolInternalRefs: new Map(),
    moduleInitRefs: new Set(),
    namespaceReexports: new Map(),
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
          info.namespaceReexports.set(stmt.exportClause.name.text, target)
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
      // Recognize destructured dynamic imports (`const { foo } = await import('./mod.ts')`) as
      // wired consumers without adding static module-load cycle edges to `info.runtimeDeps`.
      if (
        ts.isVariableDeclaration(node)
        && ts.isObjectBindingPattern(node.name)
        && node.initializer
        && ts.isAwaitExpression(node.initializer)
        && ts.isCallExpression(node.initializer.expression)
        && node.initializer.expression.expression.kind === ts.SyntaxKind.ImportKeyword
        && node.initializer.expression.arguments.length === 1
        && ts.isStringLiteral(node.initializer.expression.arguments[0]!)
      ) {
        const target = resolveLocalSpecifier(rootDir, relPath, node.initializer.expression.arguments[0]!.text)
        if (target) {
          for (const el of node.name.elements) {
            if (!ts.isIdentifier(el.name)) continue
            const localName = el.name.text
            const importedName = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : localName
            if (!info.namedImports.has(localName)) {
              info.namedImports.set(localName, { from: target, importedName })
            }
          }
        }
      }
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

    // Record per-symbol internal references & eager module-init references for reachability walk.
    const recordSymbolRefs = (symName: string, refs: ReadonlySet<string>) => {
      let set = info.symbolInternalRefs.get(symName)
      if (!set) { set = new Set(); info.symbolInternalRefs.set(symName, set) }
      for (const r of refs) {
        if (r !== symName) set.add(r)
      }
    }
    if (ts.isExportAssignment(stmt) && !stmt.isExportEquals) {
      recordSymbolRefs('default', stmtRefs)
    } else if (ownNames.size > 0) {
      const isDefaultExport = hasExportModifier(stmt) && hasDefaultModifier(stmt)
      for (const symName of ownNames) {
        recordSymbolRefs(symName, stmtRefs)
      }
      if (isDefaultExport) {
        recordSymbolRefs('default', stmtRefs)
      }
      // Variable statements whose initializers execute eagerly (not pure function/arrow defs)
      // also contribute to moduleInitRefs when the module is loaded.
      if (ts.isVariableStatement(stmt)) {
        const allLazyFns = stmt.declarationList.declarations.every(
          d => d.initializer && (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer)),
        )
        if (!allLazyFns) {
          for (const ref of stmtRefs) info.moduleInitRefs.add(ref)
        }
      }
    } else if (
      !ts.isImportDeclaration(stmt)
      && !ts.isExportDeclaration(stmt)
      && !ts.isInterfaceDeclaration(stmt)
      && !ts.isTypeAliasDeclaration(stmt)
      && !(ts.isFunctionDeclaration(stmt) && !stmt.body)
    ) {
      for (const ref of stmtRefs) info.moduleInitRefs.add(ref)
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
  ownModuleUsedKeys: Set<string>
  liveDocKeys: Set<string>
  unwired: UnwiredExportFinding[]
  declaredBySymbol: Map<string, string[]>
  testImportersByKey: Map<string, Set<string>>
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
  const ownModuleUsedKeys = new Set<string>()
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
      } else if (usedInternallyInModule) {
        // Own-module-only noise filter (R2-03): exported symbol is called internally inside a
        // production-consumed module, so it is live code rather than a cross-module dead primitive.
        ownModuleUsedKeys.add(key)
        liveDocKeys.add(key)
      } else {
        const testImporters = [...(testImportersByKey.get(key) ?? [])].sort()
        unwired.push({
          key,
          file: info.relPath,
          symbol: sym,
          kind: testImporters.length > 0 ? 'test_only' : 'unreferenced',
          usedInternallyInModule: false,
          testImporters,
        })
      }
    }
  }

  return { totalServerValueExports, wiredKeys, ownModuleUsedKeys, liveDocKeys, unwired, declaredBySymbol, testImportersByKey }
}

/**
 * Production-entrypoint value-reference reachability walk (R3-09).
 *
 * Unlike syntactic `prodUsed` (which counts imports from any non-test file, even dead modules,
 * and filters out `usedInternallyInModule` even when the caller itself is dead), this performs
 * a symbol-level BFS rooted strictly at declared production entrypoints (`src/server.ts`,
 * `src/actions.ts`, `src/routes/**`, `src/router.tsx`, `src/client.tsx`, `worker/**`,
 * `scripts/**`, plus `src/server/execution.ts::Execution`).
 *
 * Classifies every declared value export in `src/server/**` into exactly one of:
 *   - `reachable`: reached via value references / module-init edges from a production entrypoint
 *   - `testOnly`: NOT reachable from production entrypoints, imported by >=1 test file
 *   - `unreachable`: NOT reachable from production entrypoints and NOT imported by any test
 */
export function analyzeProductionReachability(
  files: Map<string, ParsedFileInfo>,
  testImportersByKey: Map<string, Set<string>>,
): ReachabilitySummary {
  const loadedModules = new Set<string>()
  const reachedSymbols = new Set<string>() // key: `${file}::${symbolName}`
  const symQueue: Array<{ file: string; sym: string }> = []

  const markSymbol = (file: string, sym: string): void => {
    const key = `${file}::${sym}`
    if (reachedSymbols.has(key)) return
    reachedSymbols.add(key)
    symQueue.push({ file, sym })
  }

  const loadModule = (file: string): void => {
    if (loadedModules.has(file)) return
    const info = files.get(file)
    if (!info || info.isTest) return
    loadedModules.add(file)
    for (const ref of info.moduleInitRefs) {
      markSymbol(file, ref)
    }
    for (const sideTarget of info.sideEffectImports) {
      loadModule(sideTarget)
    }
  }

  const markAllExports = (file: string, seen = new Set<string>()): void => {
    if (seen.has(file)) return
    seen.add(file)
    const info = files.get(file)
    if (!info || info.isTest) return
    loadModule(file)
    for (const exp of info.declaredValueExports) markSymbol(file, exp)
    for (const exp of info.reexports.keys()) markSymbol(file, exp)
    for (const starTarget of info.starReexports) markAllExports(starTarget, seen)
  }

  let entrypoints = 0
  for (const info of files.values()) {
    if (!isReachabilityEntrypoint(info.relPath)) continue
    entrypoints += 1
    loadModule(info.relPath)
    for (const exp of info.declaredValueExports) markSymbol(info.relPath, exp)
    for (const exp of info.reexports.keys()) markSymbol(info.relPath, exp)
    for (const starTarget of info.starReexports) markAllExports(starTarget)
  }
  if (files.has('src/server/execution.ts')) {
    loadModule('src/server/execution.ts')
    markSymbol('src/server/execution.ts', 'Execution')
  }

  while (symQueue.length > 0) {
    const { file, sym } = symQueue.shift()!
    const info = files.get(file)
    if (!info || info.isTest) continue
    loadModule(file)

    // 1. Named import in `file` -> target module export
    const namedImp = info.namedImports.get(sym)
    if (namedImp) {
      loadModule(namedImp.from)
      markSymbol(namedImp.from, namedImp.importedName)
    }

    // 2. Namespace import in `file` -> accessed props or all exports
    const nsTarget = info.namespaceImports.get(sym)
    if (nsTarget) {
      loadModule(nsTarget)
      if (info.wholeNamespacesUsed.has(sym)) {
        markAllExports(nsTarget)
      } else {
        for (const prop of info.namespaceProps.get(sym) ?? []) {
          markSymbol(nsTarget, prop)
        }
      }
    }

    // 3. Exported local alias (`export { local as exported }`)
    const localAlias = info.localExportAliases.get(sym)
    if (localAlias) {
      markSymbol(file, localAlias)
    }

    // 4. Direct re-export (`export { a as b } from './x'`)
    const reexp = info.reexports.get(sym)
    if (reexp) {
      loadModule(reexp.from)
      markSymbol(reexp.from, reexp.importedName)
    }

    // 5. Namespace re-export (`export * as ns from './x'`)
    const nsReexpTarget = info.namespaceReexports.get(sym)
    if (nsReexpTarget) {
      markAllExports(nsReexpTarget)
    }

    // 6. Star re-export passthrough (`export * from './x'`)
    if (!info.declaredValueExports.has(sym) && !reexp && !localAlias && info.starReexports.size > 0) {
      for (const starTarget of info.starReexports) {
        loadModule(starTarget)
        markSymbol(starTarget, sym)
      }
    }

    // 7. Local declaration body references -> follow intra-module call/value edges
    const internalRefs = info.symbolInternalRefs.get(sym)
    if (internalRefs) {
      for (const ref of internalRefs) {
        markSymbol(file, ref)
      }
    }
  }

  let reachable = 0
  const testOnlyKeys: string[] = []
  const unreachableKeys: string[] = []

  const serverFiles = [...files.values()]
    .filter(f => f.relPath.startsWith('src/server/') && !f.isTest)
    .sort((a, b) => a.relPath.localeCompare(b.relPath))

  for (const info of serverFiles) {
    for (const sym of [...info.declaredValueExports].sort()) {
      const key = `${info.relPath}::${sym}`
      if (reachedSymbols.has(key)) {
        reachable += 1
      } else if ((testImportersByKey.get(key)?.size ?? 0) > 0) {
        testOnlyKeys.push(key)
      } else {
        unreachableKeys.push(key)
      }
    }
  }

  return {
    entrypoints,
    reachable,
    testOnly: testOnlyKeys.length,
    unreachable: unreachableKeys.length,
    testOnlyKeys,
    unreachableKeys,
  }
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

function todayIsoDate(): string {
  return new Date().toISOString().slice(0, 10)
}

function isValidIsoDate(s: string): boolean {
  if (!ISO_DATE_RE.test(s)) return false
  const ms = Date.parse(`${s}T00:00:00Z`)
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 10) === s
}

export function runUnwiredCheck(options: {
  rootDir?: string
  baselinePath?: string
  baseline?: UnwiredBaseline
  docRelPath?: string
  now?: string
} = {}): UnwiredCheckResult {
  const started = Date.now()
  const rootDir = resolve(options.rootDir ?? join(dirname(fileURLToPath(import.meta.url)), '..'))
  const baselinePath = options.baselinePath ?? join(rootDir, 'scripts/unwired-baseline.json')
  const baseline = options.baseline ?? loadUnwiredBaseline(baselinePath)
  const nowDate = options.now ?? todayIsoDate()

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

  // 2. Unwired / test-only value exports (with own-module noise filtered out)
  const {
    totalServerValueExports,
    wiredKeys,
    ownModuleUsedKeys,
    liveDocKeys,
    unwired,
    declaredBySymbol,
    testImportersByKey,
  } = analyzeUnwiredExports(parsedFiles)
  const unwiredKeySet = new Set(unwired.map(u => u.key))

  // 2b. Production-entrypoint reachability walk (R3-09; warn-only during rollout batch)
  const reachability = analyzeProductionReachability(parsedFiles, testImportersByKey)

  const invalidKeepUnwired: string[] = []
  const staleKeepUnwired: StaleKeepUnwiredEntry[] = []
  const keepSet = new Set<string>()
  for (const entry of baseline.keepUnwired) {
    if (entry.disposition !== 'keep-unwired' || !entry.ticket?.trim() || !entry.reason?.trim()) {
      invalidKeepUnwired.push(entry.key)
    } else {
      keepSet.add(entry.key)
    }
    if (!unwiredKeySet.has(entry.key)) {
      const status: StaleKeepUnwiredEntry['status'] = wiredKeys.has(entry.key)
        ? 'wired_externally'
        : ownModuleUsedKeys.has(entry.key)
          ? 'wired_internally'
          : 'deleted'
      staleKeepUnwired.push({ key: entry.key, status })
    }
  }
  const baselinedSet = new Set(baseline.baselinedExports)

  const newUnwiredExports = unwired.filter(u => !keepSet.has(u.key) && !baselinedSet.has(u.key))
  const resolvedBaselineExports = baseline.baselinedExports.filter(k => !unwiredKeySet.has(k))

  // Validate ticketed additions metadata (if present).
  const invalidTicketedAdditions: string[] = []
  for (const ta of baseline.ticketedAdditions ?? []) {
    if (!ta.key?.trim() || !ta.owner?.trim() || !ta.ticket?.trim() || !isValidIsoDate(ta.expires ?? '')) {
      invalidTicketedAdditions.push(`${ta.key || '(missing key)'}: requires non-empty owner, ticket, and YYYY-MM-DD expires`)
    } else if (ta.expires < nowDate) {
      invalidTicketedAdditions.push(`${ta.key}: expired on ${ta.expires} (owner=${ta.owner}, ticket=${ta.ticket})`)
    } else if (!baselinedSet.has(ta.key)) {
      invalidTicketedAdditions.push(`${ta.key}: stale ticketedAddition not present in baselinedExports`)
    }
  }

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
    && resolvedBaselineExports.length === 0
    && invalidKeepUnwired.length === 0
    && staleKeepUnwired.length === 0
    && invalidTicketedAdditions.length === 0
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
    ownModuleOnlyExportCount: ownModuleUsedKeys.size,
    unwiredExports: unwired,
    newUnwiredExports,
    resolvedBaselineExports,
    invalidKeepUnwired,
    staleKeepUnwired,
    invalidTicketedAdditions,
    staleDocCitations,
    reachability,
    durationMs: Date.now() - started,
  }
}

export function buildBaselineFromResult(
  result: UnwiredCheckResult,
  existingKeepUnwired: readonly KeepUnwiredEntry[] = DEFAULT_KEEP_UNWIRED,
  existingTicketedAdditions: readonly TicketedBaselineAddition[] = [],
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
  const baselinedSet = new Set(baselinedExports)
  const ticketedAdditions = existingTicketedAdditions
    .filter(ta => baselinedSet.has(ta.key))
    .sort((a, b) => a.key.localeCompare(b.key))
  const out: UnwiredBaseline = {
    version: 1,
    allowedCycles: [...result.cycles].sort(),
    keepUnwired,
    baselinedExports,
  }
  if (ticketedAdditions.length > 0) out.ticketedAdditions = ticketedAdditions
  return out
}

export interface UpdateBaselineOptions {
  rootDir: string
  baselinePath: string
  allowAddWithTicket?: boolean
  defaultTicketMeta?: { owner: string; ticket: string; expires: string } | null
  perEntryTickets?: readonly TicketedBaselineAddition[]
  now?: string
}

export interface UpdateBaselineResult {
  ok: boolean
  wrote: boolean
  addedExports: string[]
  addedCycles: string[]
  removedExports: string[]
  removedKeepUnwired: string[]
  baseline: UnwiredBaseline | null
  error?: string
}

/**
 * Monotone baseline writer (R2-03):
 * - Default mode is REMOVAL-ONLY: prunes resolved exports, fixed cycles, and stale keepUnwired
 *   entries, and REFUSES to add any new unwired exports or cycles.
 * - With `allowAddWithTicket: true`, new unwired exports are allowed ONLY when every added key
 *   carries valid `{ owner, ticket, expires }` metadata (non-empty owner/ticket, valid future/current
 *   YYYY-MM-DD expiry). New runtime import cycles are always refused.
 */
export function updateBaselineMonotone(opts: UpdateBaselineOptions): UpdateBaselineResult {
  const nowDate = opts.now ?? todayIsoDate()
  const existing: UnwiredBaseline = existsSync(opts.baselinePath)
    ? loadUnwiredBaseline(opts.baselinePath)
    : { version: 1, allowedCycles: [], keepUnwired: [...DEFAULT_KEEP_UNWIRED], baselinedExports: [] }
  const mergedKeep = existing.keepUnwired.length > 0 ? existing.keepUnwired : [...DEFAULT_KEEP_UNWIRED]
  const scan = runUnwiredCheck({
    rootDir: opts.rootDir,
    baseline: { version: 1, allowedCycles: [], keepUnwired: [...mergedKeep], baselinedExports: [] },
    now: nowDate,
  })
  const candidate = buildBaselineFromResult(scan, mergedKeep, existing.ticketedAdditions ?? [])

  const existingExports = new Set(existing.baselinedExports)
  const existingCycles = new Set(existing.allowedCycles)
  const nextExportsSet = new Set(candidate.baselinedExports)
  const nextKeepSet = new Set(candidate.keepUnwired.map(k => k.key))

  const addedExports = candidate.baselinedExports.filter(k => !existingExports.has(k))
  const addedCycles = candidate.allowedCycles.filter(c => !existingCycles.has(c))
  const removedExports = existing.baselinedExports.filter(k => !nextExportsSet.has(k))
  const removedKeepUnwired = existing.keepUnwired.map(k => k.key).filter(k => !nextKeepSet.has(k))

  if (addedCycles.length > 0) {
    return {
      ok: false,
      wrote: false,
      addedExports,
      addedCycles,
      removedExports,
      removedKeepUnwired,
      baseline: null,
      error: `Refusing to add ${addedCycles.length} new runtime import cycle(s) to baseline: ${addedCycles.join('; ')}`,
    }
  }

  if (addedExports.length > 0 && !opts.allowAddWithTicket) {
    return {
      ok: false,
      wrote: false,
      addedExports,
      addedCycles: [],
      removedExports,
      removedKeepUnwired,
      baseline: null,
      error:
        `--write-baseline is removal-only by default; refusing to add ${addedExports.length} new unwired export(s): `
        + `${addedExports.slice(0, 8).join(', ')}${addedExports.length > 8 ? ` (+${addedExports.length - 8} more)` : ''}. `
        + `Wire/delete them or pass --allow-add-with-ticket with explicit { owner, ticket, expires } metadata.`,
    }
  }

  if (addedExports.length > 0 && opts.allowAddWithTicket) {
    const byKey = new Map<string, TicketedBaselineAddition>()
    for (const existingTa of candidate.ticketedAdditions ?? []) byKey.set(existingTa.key, existingTa)
    for (const entry of opts.perEntryTickets ?? []) byKey.set(entry.key, entry)

    const missingOrInvalid: string[] = []
    for (const key of addedExports) {
      const meta = byKey.get(key) ?? (opts.defaultTicketMeta ? { key, ...opts.defaultTicketMeta } : null)
      if (!meta || !meta.owner?.trim() || !meta.ticket?.trim() || !isValidIsoDate(meta.expires ?? '')) {
        missingOrInvalid.push(`${key} (missing valid { owner, ticket, expires })`)
      } else if (meta.expires < nowDate) {
        missingOrInvalid.push(`${key} (expires ${meta.expires} is in the past vs ${nowDate})`)
      } else {
        byKey.set(key, {
          key,
          owner: meta.owner.trim(),
          ticket: meta.ticket.trim(),
          expires: meta.expires.trim(),
        })
      }
    }
    if (missingOrInvalid.length > 0) {
      return {
        ok: false,
        wrote: false,
        addedExports,
        addedCycles: [],
        removedExports,
        removedKeepUnwired,
        baseline: null,
        error: `--allow-add-with-ticket requires valid { owner, ticket, expires } for every added export: ${missingOrInvalid.join('; ')}`,
      }
    }
    candidate.ticketedAdditions = [...byKey.values()]
      .filter(ta => nextExportsSet.has(ta.key))
      .sort((a, b) => a.key.localeCompare(b.key))
  }

  writeFileSync(opts.baselinePath, `${JSON.stringify(candidate, null, 2)}\n`, 'utf8')
  return {
    ok: true,
    wrote: true,
    addedExports,
    addedCycles: [],
    removedExports,
    removedKeepUnwired,
    baseline: candidate,
  }
}

function main(argv: string[] = process.argv.slice(2)): void {
  let rootDir = resolve(join(dirname(fileURLToPath(import.meta.url)), '..'))
  let baselinePath: string | null = null
  let writeBaseline = false
  let allowAddWithTicket = false
  let json = false
  let nowDate: string | undefined
  let owner = ''
  let ticket = ''
  let expires = ''
  let addMetaPath = ''

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--json') { json = true; continue }
    if (arg === '--write-baseline') { writeBaseline = true; continue }
    if (arg === '--allow-add-with-ticket') { allowAddWithTicket = true; continue }
    if (arg === '--root') { rootDir = resolve(argv[++i] ?? ''); continue }
    if (arg === '--baseline') { baselinePath = resolve(argv[++i] ?? ''); continue }
    if (arg === '--now') { nowDate = argv[++i] ?? ''; continue }
    if (arg === '--owner') { owner = argv[++i] ?? ''; continue }
    if (arg === '--ticket') { ticket = argv[++i] ?? ''; continue }
    if (arg === '--expires') { expires = argv[++i] ?? ''; continue }
    if (arg === '--add-meta') { addMetaPath = resolve(argv[++i] ?? ''); continue }
    console.error(`check-unwired: unknown argument '${arg}'`)
    process.exit(2)
  }

  const resolvedBaselinePath = baselinePath ?? join(rootDir, 'scripts/unwired-baseline.json')

  if (writeBaseline) {
    let perEntryTickets: TicketedBaselineAddition[] = []
    if (addMetaPath) {
      perEntryTickets = JSON.parse(readFileSync(addMetaPath, 'utf8')) as TicketedBaselineAddition[]
    }
    const defaultTicketMeta = owner || ticket || expires ? { owner, ticket, expires } : null
    const upd = updateBaselineMonotone({
      rootDir,
      baselinePath: resolvedBaselinePath,
      allowAddWithTicket,
      defaultTicketMeta,
      perEntryTickets,
      now: nowDate,
    })
    if (json) {
      console.log(JSON.stringify(upd, null, 2))
    } else if (!upd.ok) {
      console.error(`check-unwired --write-baseline: FAIL — ${upd.error}`)
    } else {
      const b = upd.baseline!
      console.log(
        `wrote ${relative(rootDir, resolvedBaselinePath)}: cycles=${b.allowedCycles.length}, `
        + `keepUnwired=${b.keepUnwired.length}, baselinedExports=${b.baselinedExports.length} `
        + `(removed=${upd.removedExports.length}, added=${upd.addedExports.length}, prunedKeep=${upd.removedKeepUnwired.length})`,
      )
    }
    process.exit(upd.ok ? 0 : 1)
  }

  const res = runUnwiredCheck({ rootDir, baselinePath: resolvedBaselinePath, now: nowDate })
  if (json) {
    console.log(JSON.stringify(res, null, 2))
    process.exit(res.ok ? 0 : 1)
  }

  console.log(
    `check-unwired: ${res.ok ? 'PASS' : 'FAIL'} `
    + `(files=${res.filesScanned}, cycles=${res.cycles.length}, newCycles=${res.newCycles.length}, `
    + `serverExports=${res.totalServerValueExports}, wired=${res.wiredExportCount}, `
    + `ownModuleOnly=${res.ownModuleOnlyExportCount}, unwired=${res.unwiredExports.length}, `
    + `newUnwired=${res.newUnwiredExports.length}, resolvedBaseline=${res.resolvedBaselineExports.length}, `
    + `staleKeep=${res.staleKeepUnwired.length}, staleDocCitations=${res.staleDocCitations.length}, `
    + `reachability=[entrypoints=${res.reachability.entrypoints}, reachable=${res.reachability.reachable}, `
    + `testOnly=${res.reachability.testOnly}, unreachable=${res.reachability.unreachable}], ${res.durationMs}ms)`,
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
  for (const stale of res.staleKeepUnwired) {
    console.error(`FAIL [stale-keep-unwired]: ${stale.key} is now ${stale.status} — prune via: node scripts/check-unwired.ts --write-baseline`)
  }
  for (const inv of res.invalidTicketedAdditions) {
    console.error(`FAIL [invalid-ticketed-addition]: ${inv}`)
  }
  for (const exp of res.newUnwiredExports) {
    console.error(`FAIL [new-unwired-export]: ${exp.key} (${exp.kind}; tests=[${exp.testImporters.slice(0, 3).join(', ')}])`)
  }
  if (res.resolvedBaselineExports.length > 0) {
    console.error(
      `FAIL [resolved-baseline-export]: ${res.resolvedBaselineExports.length} stale baselined export(s) are now wired/internal/deleted — prune via: node scripts/check-unwired.ts --write-baseline`,
    )
    for (const k of res.resolvedBaselineExports.slice(0, 10)) {
      console.error(`  - ${k}`)
    }
    if (res.resolvedBaselineExports.length > 10) {
      console.error(`  ... (+${res.resolvedBaselineExports.length - 10} more)`)
    }
  }
  for (const cite of res.staleDocCitations) {
    console.error(`FAIL [stale-architecture-doc]: ${cite.file}:${cite.line} cites unwired symbol "${cite.symbol}" (${cite.declaringFiles.join(', ')})`)
  }
  if (res.fixedCycles.length > 0) {
    console.log(`NOTE: ${res.fixedCycles.length} baselined cycle(s) resolved and can be removed from scripts/unwired-baseline.json.`)
  }
  process.exit(res.ok ? 0 : 1)
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main()
}
