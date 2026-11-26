#!/usr/bin/env node
/**
 * AST Function-Body Clone Guard & Safety-Primitive Deduplication Ratchet (`R3-10`, Step 3).
 *
 * Fast (<2s), parser-only (`ts.createSourceFile`, no typechecker) scanner over `src/server/**\/*.ts`
 * that:
 *   1. Normalizes every function-like body spanning `>= 6` lines (stripping comments/whitespace
 *      and alpha-renaming bound parameters/locals while preserving property names, literals, and
 *      AST structure) and computes a SHA-256 body hash.
 *   2. Identifies cross-file clone groups (identical body hash in `>= 2` distinct files).
 *   3. Enforces a strictly removal-only baseline in `scripts/clone-baseline.json`:
 *        - Fails on any NEW cross-file clone group or any existing group that gains a new file.
 *        - Fails (`prune-fail`) when any baselined clone group or file is eliminated without
 *          running `--write-baseline`.
 *        - `--write-baseline` is strictly removal-only when a baseline already exists.
 *   4. Hard safety-primitive invariant:
 *        - Asserts **0** AST clone groups touching `src/server/safety-primitives.ts` or any
 *          watched safety primitive (`isSensitiveRepoEntry`, `isSensitiveRepoRelativePath`,
 *          `constantTimeStringEqual`).
 *        - Asserts **0** unticketed duplicate definitions of watched safety primitives outside
 *          `src/server/safety-primitives.ts` (any legacy kernel-lane debt must be explicitly
 *          recorded in `ticketedSafetyPrimitiveDebt` and is strictly removal-only).
 *
 * Usage:
 *   node scripts/check-clones.ts                    # enforce clone & safety-primitive ratchet
 *   node scripts/check-clones.ts --write-baseline   # removal-only prune of scripts/clone-baseline.json
 *   node scripts/check-clones.ts --json             # machine-readable JSON report
 */
import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import ts from 'typescript'

export const DEFAULT_CLONE_MIN_LINES = 6
export const DEFAULT_CLONE_BASELINE_FILE = 'scripts/clone-baseline.json'
export const SAFETY_PRIMITIVE_AUTHORITY_FILE = 'src/server/safety-primitives.ts'
export const SAFETY_PRIMITIVE_NAMES: ReadonlySet<string> = new Set([
  'isSensitiveRepoEntry',
  'isSensitiveRepoRelativePath',
  'constantTimeStringEqual',
])

export interface FunctionBodyCloneMember {
  file: string
  name: string
  startLine: number
  endLine: number
  lines: number
}

export interface CloneGroup {
  hash: string
  lines: number
  files: string[]
  members: FunctionBodyCloneMember[]
  involvesSafetyPrimitive: boolean
}

export interface SafetyPrimitiveDuplicate {
  name: string
  file: string
  startLine: number
  endLine: number
  lines: number
}

export interface TicketedSafetyPrimitiveDebt {
  name: string
  file: string
  ticket: string
  reason: string
}

export interface CloneBaselineGroup {
  hash: string
  lines: number
  files: string[]
  sampleNames: string[]
  note?: string
}

export interface CloneBaseline {
  version: 1
  dir: string
  minLines: number
  groups: CloneBaselineGroup[]
  ticketedSafetyPrimitiveDebt: TicketedSafetyPrimitiveDebt[]
}

export interface CloneCheckOptions {
  rootDir?: string
  dir?: string
  minLines?: number
  baselineFile?: string
  writeBaseline?: boolean
  /** Optional default ticketed debt entries used only when bootstrapping a new baseline. */
  bootstrapSafetyDebt?: TicketedSafetyPrimitiveDebt[]
}

export interface CloneCheckReport {
  ok: boolean
  dir: string
  minLines: number
  baselinePath: string
  baselineExists: boolean
  filesScanned: number
  functionsScanned: number
  candidateFunctions: number
  cloneGroups: CloneGroup[]
  safetyPrimitiveAstCloneGroups: CloneGroup[]
  safetyPrimitiveDuplicates: SafetyPrimitiveDuplicate[]
  unticketedSafetyPrimitiveDuplicates: SafetyPrimitiveDuplicate[]
  resolvedSafetyPrimitiveDebt: TicketedSafetyPrimitiveDebt[]
  newCloneGroups: CloneGroup[]
  expandedCloneGroups: Array<{ hash: string; addedFiles: string[]; baselineFiles: string[]; actualFiles: string[] }>
  resolvedCloneGroups: CloneBaselineGroup[]
  shrunkCloneGroups: Array<{ hash: string; removedFiles: string[]; baselineFiles: string[]; actualFiles: string[] }>
  wroteBaselinePath?: string
  error?: string
  durationMs: number
}

/** Default coordinator-approved R3-11 debt entry when bootstrapping the initial baseline. */
export const DEFAULT_BOOTSTRAP_SAFETY_DEBT: readonly TicketedSafetyPrimitiveDebt[] = [
  {
    name: 'isSensitiveRepoEntry',
    file: 'src/server/exec-verify.ts',
    ticket: 'R3-11',
    reason: 'Kernel-lane file deferred to R3-11 (R3-05 review lane) to retire final duplicate into safety-primitives.ts.',
  },
  {
    name: 'isSensitiveRepoRelativePath',
    file: 'src/server/exec-verify.ts',
    ticket: 'R3-11',
    reason: 'Kernel-lane file deferred to R3-11 (R3-05 review lane) to retire final duplicate into safety-primitives.ts.',
  },
]

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
  }
  return '<anonymous>'
}

function collectBindingNames(name: ts.BindingName, locals: Map<string, string>): void {
  if (ts.isIdentifier(name)) {
    if (!locals.has(name.text)) locals.set(name.text, `$L${locals.size}`)
    return
  }
  for (const el of name.elements) {
    if (ts.isBindingElement(el)) {
      collectBindingNames(el.name, locals)
    }
  }
}

function collectLocalBindings(fn: ts.FunctionLikeDeclarationBase): Map<string, string> {
  const locals = new Map<string, string>()
  for (const param of fn.parameters) {
    collectBindingNames(param.name, locals)
  }
  if (!fn.body) return locals
  const walk = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node)) {
      collectBindingNames(node.name, locals)
    } else if (ts.isCatchClause(node) && node.variableDeclaration) {
      collectBindingNames(node.variableDeclaration.name, locals)
    }
    ts.forEachChild(node, walk)
  }
  walk(fn.body)
  return locals
}

function isNonLocalIdentifierPosition(node: ts.Identifier): boolean {
  const parent = node.parent
  if (!parent) return false
  if (ts.isPropertyAccessExpression(parent) && parent.name === node) return true
  if (ts.isPropertyAssignment(parent) && parent.name === node) return true
  if (ts.isMethodDeclaration(parent) && parent.name === node) return true
  if (ts.isPropertySignature(parent) && parent.name === node) return true
  if (ts.isMethodSignature(parent) && parent.name === node) return true
  if (ts.isTypeReferenceNode(parent) && parent.typeName === node) return true
  if (ts.isQualifiedName(parent) && parent.right === node) return true
  if (ts.isLabeledStatement(parent) && parent.label === node) return true
  return false
}

/** Produce a deterministic, whitespace/comment-free, alpha-renamed AST signature for a function body. */
export function normalizeFunctionBodyAst(fn: ts.FunctionLikeDeclarationBase): string {
  if (!fn.body) return ''
  const locals = collectLocalBindings(fn)
  const parts: string[] = []

  const serialize = (node: ts.Node): void => {
    if (ts.isJSDoc(node)) return
    const kind = ts.SyntaxKind[node.kind]
    if (ts.isIdentifier(node)) {
      if (isNonLocalIdentifierPosition(node)) {
        parts.push(`P:${node.text}`)
      } else {
        const mapped = locals.get(node.text)
        parts.push(mapped ? `V:${mapped}` : `I:${node.text}`)
      }
      return
    }
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      parts.push(`S:${JSON.stringify(node.text)}`)
      return
    }
    if (ts.isNumericLiteral(node)) {
      parts.push(`N:${node.text}`)
      return
    }
    if (ts.isRegularExpressionLiteral(node)) {
      parts.push(`R:${node.text}`)
      return
    }
    if (ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
      parts.push(`T:${JSON.stringify(node.text)}`)
      return
    }
    parts.push(`(${kind}`)
    ts.forEachChild(node, child => {
      parts.push(' ')
      serialize(child)
    })
    parts.push(')')
  }

  serialize(fn.body)
  return parts.join('')
}

export function hashFunctionBodyAst(fn: ts.FunctionLikeDeclarationBase): string {
  const normalized = normalizeFunctionBodyAst(fn)
  return createHash('sha256').update(normalized).digest('hex').slice(0, 16)
}

function collectTsFiles(dir: string): string[] {
  const results: string[] = []
  const visit = (current: string) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = join(current, entry.name)
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') continue
        visit(full)
      } else if (
        entry.isFile() &&
        entry.name.endsWith('.ts') &&
        !entry.name.endsWith('.d.ts') &&
        !entry.name.endsWith('.test.ts') &&
        !entry.name.endsWith('.spec.ts')
      ) {
        results.push(full)
      }
    }
  }
  visit(dir)
  results.sort()
  return results
}

function scanSourceForClones(
  source: string,
  fileLabel: string,
  minLines: number,
): {
  totalFunctions: number
  candidates: Array<{ hash: string; member: FunctionBodyCloneMember }>
  safetyPrimitiveDefs: SafetyPrimitiveDuplicate[]
} {
  const sf = ts.createSourceFile(fileLabel, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  let totalFunctions = 0
  const candidates: Array<{ hash: string; member: FunctionBodyCloneMember }> = []
  const safetyPrimitiveDefs: SafetyPrimitiveDuplicate[] = []

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
      totalFunctions += 1
      const name = resolveFunctionName(node)
      const startLine = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
      const endLine = sf.getLineAndCharacterOfPosition(node.getEnd()).line + 1
      const bodyStartLine = sf.getLineAndCharacterOfPosition(node.body.getStart(sf)).line + 1
      const bodyEndLine = sf.getLineAndCharacterOfPosition(node.body.getEnd()).line + 1
      const bodyLines = bodyEndLine - bodyStartLine + 1
      const fnLines = endLine - startLine + 1

      if (SAFETY_PRIMITIVE_NAMES.has(name) && fileLabel !== SAFETY_PRIMITIVE_AUTHORITY_FILE) {
        safetyPrimitiveDefs.push({ name, file: fileLabel, startLine, endLine, lines: fnLines })
      }

      if (bodyLines >= minLines) {
        const hash = hashFunctionBodyAst(node)
        candidates.push({
          hash,
          member: {
            file: fileLabel,
            name,
            startLine,
            endLine,
            lines: bodyLines,
          },
        })
      }
    }
    ts.forEachChild(node, visit)
  }

  visit(sf)
  return { totalFunctions, candidates, safetyPrimitiveDefs }
}

export function loadCloneBaseline(baselinePath: string): CloneBaseline | null {
  if (!existsSync(baselinePath)) return null
  const parsed = JSON.parse(readFileSync(baselinePath, 'utf8')) as CloneBaseline
  return {
    version: 1,
    dir: parsed.dir ?? 'src/server',
    minLines: parsed.minLines ?? DEFAULT_CLONE_MIN_LINES,
    groups: Array.isArray(parsed.groups) ? parsed.groups : [],
    ticketedSafetyPrimitiveDebt: Array.isArray(parsed.ticketedSafetyPrimitiveDebt)
      ? parsed.ticketedSafetyPrimitiveDebt
      : [],
  }
}

function debtKey(entry: { name: string; file: string }): string {
  return `${entry.file}::${entry.name}`
}

/** Run the AST clone & safety-primitive guard over `src/server/**`. */
export function runCloneCheck(options: CloneCheckOptions = {}): CloneCheckReport {
  const t0 = Date.now()
  const rootDir = resolve(options.rootDir ?? join(fileURLToPath(import.meta.url), '../..'))
  const targetDir = resolve(rootDir, options.dir ?? 'src/server')
  const relDir = relative(rootDir, targetDir).replace(/\\/g, '/') || '.'
  const minLines = Math.max(1, options.minLines ?? DEFAULT_CLONE_MIN_LINES)
  const baselineAbs = resolve(rootDir, options.baselineFile ?? DEFAULT_CLONE_BASELINE_FILE)
  const baselineRel = relative(rootDir, baselineAbs).replace(/\\/g, '/')

  const files = collectTsFiles(targetDir)
  let functionsScanned = 0
  let candidateFunctions = 0
  const byHash = new Map<string, FunctionBodyCloneMember[]>()
  const safetyPrimitiveDuplicates: SafetyPrimitiveDuplicate[] = []

  for (const absPath of files) {
    if (!statSync(absPath).isFile()) continue
    const rel = relative(rootDir, absPath).replace(/\\/g, '/')
    const source = readFileSync(absPath, 'utf8')
    const scanned = scanSourceForClones(source, rel, minLines)
    functionsScanned += scanned.totalFunctions
    candidateFunctions += scanned.candidates.length
    for (const def of scanned.safetyPrimitiveDefs) safetyPrimitiveDuplicates.push(def)
    for (const c of scanned.candidates) {
      const list = byHash.get(c.hash) ?? []
      list.push(c.member)
      byHash.set(c.hash, list)
    }
  }

  safetyPrimitiveDuplicates.sort((a, b) => a.file.localeCompare(b.file) || a.name.localeCompare(b.name))

  const cloneGroups: CloneGroup[] = []
  for (const [hash, members] of byHash) {
    const distinctFiles = [...new Set(members.map(m => m.file))].sort()
    if (distinctFiles.length < 2) continue
    members.sort((a, b) => a.file.localeCompare(b.file) || a.startLine - b.startLine)
    const involvesSafetyPrimitive = members.some(
      m => m.file === SAFETY_PRIMITIVE_AUTHORITY_FILE || SAFETY_PRIMITIVE_NAMES.has(m.name),
    )
    cloneGroups.push({
      hash,
      lines: Math.max(...members.map(m => m.lines)),
      files: distinctFiles,
      members,
      involvesSafetyPrimitive,
    })
  }
  cloneGroups.sort((a, b) => b.lines - a.lines || a.hash.localeCompare(b.hash))

  const safetyPrimitiveAstCloneGroups = cloneGroups.filter(g => g.involvesSafetyPrimitive)
  const existing = loadCloneBaseline(baselineAbs)

  if (options.writeBaseline) {
    if (safetyPrimitiveAstCloneGroups.length > 0) {
      return {
        ok: false,
        dir: relDir,
        minLines,
        baselinePath: baselineRel,
        baselineExists: Boolean(existing),
        filesScanned: files.length,
        functionsScanned,
        candidateFunctions,
        cloneGroups,
        safetyPrimitiveAstCloneGroups,
        safetyPrimitiveDuplicates,
        unticketedSafetyPrimitiveDuplicates: safetyPrimitiveDuplicates,
        resolvedSafetyPrimitiveDebt: [],
        newCloneGroups: [],
        expandedCloneGroups: [],
        resolvedCloneGroups: [],
        shrunkCloneGroups: [],
        error: `Refusing --write-baseline: ${safetyPrimitiveAstCloneGroups.length} safety-primitive AST clone group(s) detected.`,
        durationMs: Date.now() - t0,
      }
    }

    if (existing) {
      const baseGroupMap = new Map(existing.groups.map(g => [g.hash, g]))
      const newCloneGroups = cloneGroups.filter(g => !baseGroupMap.has(g.hash))
      const expandedCloneGroups: CloneCheckReport['expandedCloneGroups'] = []
      for (const g of cloneGroups) {
        const base = baseGroupMap.get(g.hash)
        if (!base) continue
        const baseFileSet = new Set(base.files)
        const addedFiles = g.files.filter(f => !baseFileSet.has(f))
        if (addedFiles.length > 0) {
          expandedCloneGroups.push({
            hash: g.hash,
            addedFiles,
            baselineFiles: base.files,
            actualFiles: g.files,
          })
        }
      }
      const existingDebtSet = new Set(existing.ticketedSafetyPrimitiveDebt.map(debtKey))
      const unticketedSafetyPrimitiveDuplicates = safetyPrimitiveDuplicates.filter(d => !existingDebtSet.has(debtKey(d)))

      if (newCloneGroups.length > 0 || expandedCloneGroups.length > 0 || unticketedSafetyPrimitiveDuplicates.length > 0) {
        return {
          ok: false,
          dir: relDir,
          minLines,
          baselinePath: baselineRel,
          baselineExists: true,
          filesScanned: files.length,
          functionsScanned,
          candidateFunctions,
          cloneGroups,
          safetyPrimitiveAstCloneGroups,
          safetyPrimitiveDuplicates,
          unticketedSafetyPrimitiveDuplicates,
          resolvedSafetyPrimitiveDebt: [],
          newCloneGroups,
          expandedCloneGroups,
          resolvedCloneGroups: [],
          shrunkCloneGroups: [],
          error:
            `Refusing --write-baseline: clone baseline is strictly removal-only, but found ` +
            `${newCloneGroups.length} new group(s), ${expandedCloneGroups.length} expanded group(s), ` +
            `and ${unticketedSafetyPrimitiveDuplicates.length} unticketed safety-primitive duplicate(s).`,
          durationMs: Date.now() - t0,
        }
      }

      const activeDupKeys = new Set(safetyPrimitiveDuplicates.map(debtKey))
      const nextBaseline: CloneBaseline = {
        version: 1,
        dir: relDir,
        minLines,
        groups: cloneGroups
          .map(g => {
            const prev = baseGroupMap.get(g.hash)
            const entry: CloneBaselineGroup = {
              hash: g.hash,
              lines: g.lines,
              files: g.files,
              sampleNames: [...new Set(g.members.map(m => m.name))].sort(),
            }
            if (prev?.note) entry.note = prev.note
            return entry
          })
          .sort((a, b) => a.hash.localeCompare(b.hash)),
        ticketedSafetyPrimitiveDebt: existing.ticketedSafetyPrimitiveDebt
          .filter(d => activeDupKeys.has(debtKey(d)))
          .sort((a, b) => a.file.localeCompare(b.file) || a.name.localeCompare(b.name)),
      }
      writeFileSync(baselineAbs, `${JSON.stringify(nextBaseline, null, 2)}\n`, 'utf8')
      return {
        ok: true,
        dir: relDir,
        minLines,
        baselinePath: baselineRel,
        baselineExists: true,
        filesScanned: files.length,
        functionsScanned,
        candidateFunctions,
        cloneGroups,
        safetyPrimitiveAstCloneGroups,
        safetyPrimitiveDuplicates,
        unticketedSafetyPrimitiveDuplicates: [],
        resolvedSafetyPrimitiveDebt: [],
        newCloneGroups: [],
        expandedCloneGroups: [],
        resolvedCloneGroups: [],
        shrunkCloneGroups: [],
        wroteBaselinePath: baselineRel,
        durationMs: Date.now() - t0,
      }
    }

    // Bootstrap new baseline cleanly.
    const bootstrapDebt = options.bootstrapSafetyDebt ?? [...DEFAULT_BOOTSTRAP_SAFETY_DEBT]
    const activeDupKeys = new Set(safetyPrimitiveDuplicates.map(debtKey))
    const matchedBootstrapDebt = bootstrapDebt
      .filter(d => activeDupKeys.has(debtKey(d)))
      .sort((a, b) => a.file.localeCompare(b.file) || a.name.localeCompare(b.name))
    const matchedDebtKeys = new Set(matchedBootstrapDebt.map(debtKey))
    const unticketed = safetyPrimitiveDuplicates.filter(d => !matchedDebtKeys.has(debtKey(d)))
    if (unticketed.length > 0) {
      return {
        ok: false,
        dir: relDir,
        minLines,
        baselinePath: baselineRel,
        baselineExists: false,
        filesScanned: files.length,
        functionsScanned,
        candidateFunctions,
        cloneGroups,
        safetyPrimitiveAstCloneGroups,
        safetyPrimitiveDuplicates,
        unticketedSafetyPrimitiveDuplicates: unticketed,
        resolvedSafetyPrimitiveDebt: [],
        newCloneGroups: [],
        expandedCloneGroups: [],
        resolvedCloneGroups: [],
        shrunkCloneGroups: [],
        error: `Refusing bootstrap --write-baseline: ${unticketed.length} unticketed safety-primitive duplicate(s) remain.`,
        durationMs: Date.now() - t0,
      }
    }

    const initialBaseline: CloneBaseline = {
      version: 1,
      dir: relDir,
      minLines,
      groups: cloneGroups
        .map(g => ({
          hash: g.hash,
          lines: g.lines,
          files: g.files,
          sampleNames: [...new Set(g.members.map(m => m.name))].sort(),
        }))
        .sort((a, b) => a.hash.localeCompare(b.hash)),
      ticketedSafetyPrimitiveDebt: matchedBootstrapDebt,
    }
    writeFileSync(baselineAbs, `${JSON.stringify(initialBaseline, null, 2)}\n`, 'utf8')
    return {
      ok: true,
      dir: relDir,
      minLines,
      baselinePath: baselineRel,
      baselineExists: true,
      filesScanned: files.length,
      functionsScanned,
      candidateFunctions,
      cloneGroups,
      safetyPrimitiveAstCloneGroups,
      safetyPrimitiveDuplicates,
      unticketedSafetyPrimitiveDuplicates: [],
      resolvedSafetyPrimitiveDebt: [],
      newCloneGroups: [],
      expandedCloneGroups: [],
      resolvedCloneGroups: [],
      shrunkCloneGroups: [],
      wroteBaselinePath: baselineRel,
      durationMs: Date.now() - t0,
    }
  }

  if (!existing) {
    return {
      ok: false,
      dir: relDir,
      minLines,
      baselinePath: baselineRel,
      baselineExists: false,
      filesScanned: files.length,
      functionsScanned,
      candidateFunctions,
      cloneGroups,
      safetyPrimitiveAstCloneGroups,
      safetyPrimitiveDuplicates,
      unticketedSafetyPrimitiveDuplicates: safetyPrimitiveDuplicates,
      resolvedSafetyPrimitiveDebt: [],
      newCloneGroups: cloneGroups,
      expandedCloneGroups: [],
      resolvedCloneGroups: [],
      shrunkCloneGroups: [],
      error: `Clone baseline not found at ${baselineRel}. Run --write-baseline to initialize.`,
      durationMs: Date.now() - t0,
    }
  }

  const actualGroupMap = new Map(cloneGroups.map(g => [g.hash, g]))
  const baseGroupMap = new Map(existing.groups.map(g => [g.hash, g]))

  const newCloneGroups = cloneGroups.filter(g => !baseGroupMap.has(g.hash))
  const resolvedCloneGroups = existing.groups.filter(g => !actualGroupMap.has(g.hash))
  const expandedCloneGroups: CloneCheckReport['expandedCloneGroups'] = []
  const shrunkCloneGroups: CloneCheckReport['shrunkCloneGroups'] = []

  for (const base of existing.groups) {
    const actual = actualGroupMap.get(base.hash)
    if (!actual) continue
    const baseSet = new Set(base.files)
    const actualSet = new Set(actual.files)
    const addedFiles = actual.files.filter(f => !baseSet.has(f))
    const removedFiles = base.files.filter(f => !actualSet.has(f))
    if (addedFiles.length > 0) {
      expandedCloneGroups.push({ hash: base.hash, addedFiles, baselineFiles: base.files, actualFiles: actual.files })
    }
    if (removedFiles.length > 0) {
      shrunkCloneGroups.push({ hash: base.hash, removedFiles, baselineFiles: base.files, actualFiles: actual.files })
    }
  }

  const ticketedDebtKeys = new Set(existing.ticketedSafetyPrimitiveDebt.map(debtKey))
  const activeDupKeys = new Set(safetyPrimitiveDuplicates.map(debtKey))
  const unticketedSafetyPrimitiveDuplicates = safetyPrimitiveDuplicates.filter(d => !ticketedDebtKeys.has(debtKey(d)))
  const resolvedSafetyPrimitiveDebt = existing.ticketedSafetyPrimitiveDebt.filter(d => !activeDupKeys.has(debtKey(d)))

  const ok =
    safetyPrimitiveAstCloneGroups.length === 0 &&
    unticketedSafetyPrimitiveDuplicates.length === 0 &&
    resolvedSafetyPrimitiveDebt.length === 0 &&
    newCloneGroups.length === 0 &&
    expandedCloneGroups.length === 0 &&
    resolvedCloneGroups.length === 0 &&
    shrunkCloneGroups.length === 0

  return {
    ok,
    dir: relDir,
    minLines,
    baselinePath: baselineRel,
    baselineExists: true,
    filesScanned: files.length,
    functionsScanned,
    candidateFunctions,
    cloneGroups,
    safetyPrimitiveAstCloneGroups,
    safetyPrimitiveDuplicates,
    unticketedSafetyPrimitiveDuplicates,
    resolvedSafetyPrimitiveDebt,
    newCloneGroups,
    expandedCloneGroups,
    resolvedCloneGroups,
    shrunkCloneGroups,
    durationMs: Date.now() - t0,
  }
}

function parseArgs(argv: string[]): CloneCheckOptions & { json: boolean } {
  const opts: CloneCheckOptions & { json: boolean } = { json: false }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--write-baseline') opts.writeBaseline = true
    else if (arg === '--json') opts.json = true
    else if (arg === '--root' && argv[i + 1]) opts.rootDir = argv[++i]!
    else if (arg === '--dir' && argv[i + 1]) opts.dir = argv[++i]!
    else if (arg === '--baseline' && argv[i + 1]) opts.baselineFile = argv[++i]!
    else if (arg === '--min-lines' && argv[i + 1]) opts.minLines = Number(argv[++i]!)
  }
  return opts
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2))
  const report = runCloneCheck(opts)
  if (opts.json) {
    console.log(JSON.stringify(report, null, 2))
  } else if (report.wroteBaselinePath) {
    console.log(
      `check-clones [WRITE-BASELINE] PASS (${report.durationMs}ms): ` +
        `wrote ${report.wroteBaselinePath} (groups=${report.cloneGroups.length}, ` +
        `safetyPrimitiveAstClones=${report.safetyPrimitiveAstCloneGroups.length}, ` +
        `ticketedSafetyDebt=${report.safetyPrimitiveDuplicates.length})`,
    )
  } else {
    const status = report.ok ? 'PASS' : 'FAIL'
    console.log(
      `check-clones ${status} (${report.durationMs}ms): ` +
        `scanned ${report.filesScanned} files, ${report.functionsScanned} functions ` +
        `(>=${report.minLines}L: ${report.candidateFunctions}) in ${report.dir} — ` +
        `cloneGroups=${report.cloneGroups.length}, new=${report.newCloneGroups.length}, ` +
        `expanded=${report.expandedCloneGroups.length}, resolved=${report.resolvedCloneGroups.length}, ` +
        `shrunk=${report.shrunkCloneGroups.length}, ` +
        `safetyPrimitiveAstClones=${report.safetyPrimitiveAstCloneGroups.length}, ` +
        `unticketedSafetyDups=${report.unticketedSafetyPrimitiveDuplicates.length}, ` +
        `resolvedSafetyDebt=${report.resolvedSafetyPrimitiveDebt.length}`,
    )
    if (report.error) console.error(`  ERROR: ${report.error}`)
    for (const g of report.safetyPrimitiveAstCloneGroups) {
      console.error(`  FAIL  safety-primitive AST clone ${g.hash} (${g.lines}L): ${g.files.join(', ')}`)
    }
    for (const d of report.unticketedSafetyPrimitiveDuplicates) {
      console.error(`  FAIL  unticketed safety-primitive duplicate ${d.name} in ${d.file}:${d.startLine}`)
    }
    for (const d of report.resolvedSafetyPrimitiveDebt) {
      console.error(
        `  PRUNE-FAIL  resolved ticketed safety-primitive debt ${d.name} in ${d.file} (${d.ticket}) — run --write-baseline`,
      )
    }
    for (const g of report.newCloneGroups) {
      const names = [...new Set(g.members.map(m => m.name))].join(', ')
      console.error(`  FAIL  new clone group ${g.hash} (${g.lines}L, ${names}): ${g.files.join(', ')}`)
    }
    for (const e of report.expandedCloneGroups) {
      console.error(`  FAIL  clone group ${e.hash} expanded to new file(s): ${e.addedFiles.join(', ')}`)
    }
    for (const r of report.resolvedCloneGroups) {
      console.error(`  PRUNE-FAIL  resolved clone group ${r.hash} (${r.sampleNames.join(', ')}) — run --write-baseline`)
    }
    for (const s of report.shrunkCloneGroups) {
      console.error(`  PRUNE-FAIL  clone group ${s.hash} removed file(s) ${s.removedFiles.join(', ')} — run --write-baseline`)
    }
  }
  if (!report.ok) process.exit(1)
}

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
if (isMain) {
  main()
}
