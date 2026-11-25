import assert from 'node:assert/strict'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import test from 'node:test'
import * as approvalJudge from '../src/server/approval-judge.ts'
import * as approvalPattern from '../src/server/approval-pattern.ts'
import * as dedupe from '../src/server/dedupe.ts'
import * as findingFingerprint from '../src/server/finding-fingerprint.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const SRC_DIR = join(REPO_ROOT, 'src')
const SERVER_DIR = join(SRC_DIR, 'server')

const PROTECTED_STORE_MODULES = [
  'server/store.ts',
  'server/store-session.ts',
  'server/store-projects.ts',
  'server/store-runs.ts',
  'server/store-findings.ts',
  'server/resource-harvest.ts',
  'server/finding-fingerprint.ts',
  'server/approval-pattern.ts',
  'server/model-settings.ts',
  'server/dedupe.ts',
  'server/approval-judge.ts',
] as const

function walkTsFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...walkTsFiles(full))
    else if (/\.(?:ts|tsx|mts)$/.test(entry.name)) out.push(full)
  }
  return out
}

function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:\\])\/\/[^\n]*/g, '$1')
}

/**
 * Extract all runtime local relative module imports/re-exports from a TypeScript file,
 * excluding type-only statements (`import type ...`, `export type ...`, or named lists where
 * every specifier is prefixed with `type`).
 */
function extractRuntimeRelativeDeps(file: string, knownFiles: ReadonlySet<string>): string[] {
  const cleaned = stripComments(readFileSync(file, 'utf8'))
  const deps = new Set<string>()

  const resolveLocal = (spec: string): string | null => {
    if (!spec.startsWith('.')) return null
    const base = resolve(dirname(file), spec)
    for (const cand of [base, `${base}.ts`, `${base}.tsx`, join(base, 'index.ts'), join(base, 'index.tsx')]) {
      if (knownFiles.has(cand)) return cand
    }
    return null
  }

  const staticRe =
    /\b(?:import|export)\s+(type\b)?([\s\S]*?)\bfrom\s*['"]([^'"]+)['"]|\bimport\s*['"]([^'"]+)['"]/g
  let match: RegExpExecArray | null
  while ((match = staticRe.exec(cleaned)) !== null) {
    if (match[4]) {
      const target = resolveLocal(match[4])
      if (target) deps.add(target)
      continue
    }
    if (match[1]) continue
    const clause = (match[2] ?? '').trim()
    const namedOnly = clause.match(/^\{([\s\S]*)\}$/)
    if (namedOnly) {
      const specifiers = namedOnly[1]!.split(',').map(s => s.trim()).filter(Boolean)
      if (specifiers.length > 0 && specifiers.every(s => /^type\s+/.test(s))) continue
    }
    const target = resolveLocal(match[3]!)
    if (target) deps.add(target)
  }

  return [...deps]
}

/** Tarjan's SCC algorithm returning every cycle (SCC of size > 1 or self-loop). */
function findRuntimeCycles(adj: ReadonlyMap<string, readonly string[]>): string[][] {
  let nextIndex = 0
  const indices = new Map<string, number>()
  const lowlink = new Map<string, number>()
  const onStack = new Set<string>()
  const stack: string[] = []
  const cycles: string[][] = []

  const visit = (v: string) => {
    indices.set(v, nextIndex)
    lowlink.set(v, nextIndex)
    nextIndex += 1
    stack.push(v)
    onStack.add(v)

    for (const w of adj.get(v) ?? []) {
      if (!indices.has(w)) {
        visit(w)
        lowlink.set(v, Math.min(lowlink.get(v)!, lowlink.get(w)!))
      } else if (onStack.has(w)) {
        lowlink.set(v, Math.min(lowlink.get(v)!, indices.get(w)!))
      }
    }

    if (lowlink.get(v) === indices.get(v)) {
      const comp: string[] = []
      while (true) {
        const w = stack.pop()!
        onStack.delete(w)
        comp.push(w)
        if (w === v) break
      }
      if (comp.length > 1 || (adj.get(v) ?? []).includes(v)) {
        cycles.push(comp.sort())
      }
    }
  }

  for (const node of adj.keys()) {
    if (!indices.has(node)) visit(node)
  }
  return cycles
}

test('arch-p1 acyclic store graph: zero runtime import cycles touching store*.ts or resource-harvest.ts', () => {
  const allFiles = walkTsFiles(SRC_DIR)
  const fileSet = new Set(allFiles)
  const adj = new Map<string, string[]>()
  for (const file of allFiles) {
    adj.set(file, extractRuntimeRelativeDeps(file, fileSet))
  }

  const cycles = findRuntimeCycles(adj)
  const protectedSet = new Set<string>(PROTECTED_STORE_MODULES)
  const offending = cycles
    .map(comp => comp.map(file => relative(SRC_DIR, file).replaceAll('\\', '/')))
    .filter(comp => comp.some(rel => protectedSet.has(rel)))

  assert.deepEqual(
    offending,
    [],
    `Detected runtime import cycle(s) involving store/leaf modules:\n${offending.map(c => `  - ${c.join(' <-> ')}`).join('\n')}`,
  )
})

test('arch-p1 leaf module isolation: finding-fingerprint.ts and approval-pattern.ts have zero local runtime deps', () => {
  const allFiles = walkTsFiles(SRC_DIR)
  const fileSet = new Set(allFiles)

  for (const leaf of ['finding-fingerprint.ts', 'approval-pattern.ts'] as const) {
    const leafPath = join(SERVER_DIR, leaf)
    const runtimeDeps = extractRuntimeRelativeDeps(leafPath, fileSet)
      .map(dep => relative(SRC_DIR, dep).replaceAll('\\', '/'))
    assert.deepEqual(runtimeDeps, [], `${leaf} must have zero local runtime dependencies, found: ${runtimeDeps.join(', ')}`)
  }

  // store-findings.ts must import pure fingerprinting helpers from finding-fingerprint.ts, never dedupe.ts.
  const findingsDeps = extractRuntimeRelativeDeps(join(SERVER_DIR, 'store-findings.ts'), fileSet)
    .map(dep => relative(SRC_DIR, dep).replaceAll('\\', '/'))
  assert.ok(findingsDeps.includes('server/finding-fingerprint.ts'), 'store-findings.ts must import finding-fingerprint.ts')
  assert.equal(findingsDeps.includes('server/dedupe.ts'), false, 'store-findings.ts must not runtime-import dedupe.ts')

  // store-runs.ts must import pure pattern helpers from approval-pattern.ts, never runtime-import approval-judge.ts.
  const runsDeps = extractRuntimeRelativeDeps(join(SERVER_DIR, 'store-runs.ts'), fileSet)
    .map(dep => relative(SRC_DIR, dep).replaceAll('\\', '/'))
  assert.ok(runsDeps.includes('server/approval-pattern.ts'), 'store-runs.ts must import approval-pattern.ts')
  assert.equal(runsDeps.includes('server/approval-judge.ts'), false, 'store-runs.ts must not runtime-import approval-judge.ts')
})

test('arch-p1 caller compatibility: dedupe.ts and approval-judge.ts re-export leaf helpers with identical references', () => {
  assert.strictEqual(dedupe.computeFindingFingerprint, findingFingerprint.computeFindingFingerprint)
  assert.strictEqual(dedupe.isOriginWideCwe, findingFingerprint.isOriginWideCwe)
  assert.strictEqual(dedupe.normalizeEndpointTemplate, findingFingerprint.normalizeEndpointTemplate)
  assert.strictEqual(dedupe.normalizeOrigin, findingFingerprint.normalizeOrigin)
  assert.strictEqual(dedupe.normalizeCwe, findingFingerprint.normalizeCwe)
  assert.strictEqual(dedupe.normalizeMutatedInput, findingFingerprint.normalizeMutatedInput)
  assert.strictEqual(dedupe.normalizeHandlerRef, findingFingerprint.normalizeHandlerRef)

  assert.strictEqual(approvalJudge.matchesApprovedEndpointPattern, approvalPattern.matchesApprovedEndpointPattern)
  assert.strictEqual(approvalJudge.normalizeApprovalPathPattern, approvalPattern.normalizeApprovalPathPattern)

  // Quick behavioral parity checks on extracted leaf helpers.
  assert.equal(findingFingerprint.isOriginWideCwe('CWE-942'), true)
  assert.equal(findingFingerprint.isOriginWideCwe('CWE-89'), false)
  assert.equal(findingFingerprint.normalizeEndpointTemplate('/api/orders/12345?sort=asc'), '/api/orders/:id')
  const fp = findingFingerprint.computeFindingFingerprint({
    origin: 'https://Example.TEST/',
    endpoint: '/api/orders/12345',
    method: 'get',
    cwe: 'CWE-639',
  })
  assert.equal(fp.key, 'https://example.test|/api/orders/:id|GET||CWE-639')

  assert.equal(approvalPattern.normalizeApprovalPathPattern('/api/items/42?x=1'), '/api/items/*')
  const pattern = { origin: 'https://example.test', method: 'POST', pathPattern: '/api/items/*', createdAt: 0 }
  const matched = approvalPattern.matchesApprovedEndpointPattern(
    { origin: 'https://example.test', method: 'POST', pathAndQuery: '/api/items/99' },
    [pattern],
  )
  assert.strictEqual(matched, pattern)
  const notMatched = approvalPattern.matchesApprovedEndpointPattern(
    { origin: 'https://example.test', method: 'POST', pathAndQuery: '/api/items/delete' },
    [pattern],
  )
  assert.equal(notMatched, undefined)
})

test('arch-p1 dead UI stub cleanup: src/components/ui/collapsible.tsx is deleted and unreferenced', () => {
  const stubPath = join(SRC_DIR, 'components', 'ui', 'collapsible.tsx')
  assert.equal(existsSync(stubPath), false, 'Unused src/components/ui/collapsible.tsx must be deleted')

  for (const dir of [SRC_DIR, join(REPO_ROOT, 'tests')]) {
    for (const file of walkTsFiles(dir)) {
      const content = readFileSync(file, 'utf8')
      assert.equal(
        /from\s+['"][^'"]*ui\/collapsible(?:\.tsx?)?['"]/.test(content),
        false,
        `Unexpected import of deleted ui/collapsible.tsx in ${relative(REPO_ROOT, file)}`,
      )
    }
  }
})
