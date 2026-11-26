/**
 * Canonical test-tier classification (`R2-02`, `plans/claude_quality_2.md` §2).
 *
 * Single source of truth for:
 *   - `KERNEL_TEST_RE`: precision-kernel, receipt, oracle, floor-recipe, dispatch-funnel,
 *     contract-canary, path-parity, and taxonomy-conformance suites (also imported by
 *     `scripts/check-contract-change.ts` in Wave 2 / R2-03).
 *   - `CORE_GATE_INVARIANT_TESTS`: merge-gate invariant suites that may NEVER be quarantined.
 *   - `SCHEMA_AUTHORITY_TESTS` & `PROVIDER_REDACTION_TESTS`: critical security/persistence
 *     suites protected under strict kernel/critical quarantine rules.
 */

import { existsSync, readFileSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

export const KERNEL_TEST_RE =
  /^tests\/.*(?:oracle|receipt|confirm-consistency|floor-recipe|verify-kernel|dispatch-funnel|contract-canary|path-parity|taxonomy-conformance).*\.test\.ts$/

export const CORE_GATE_INVARIANT_TESTS: readonly string[] = Object.freeze([
  'tests/v4-m7-orch.test.ts',
  'tests/v5-m1-wiring-correctness.test.ts',
  'tests/v5-m2-state.test.ts',
  'tests/sys-contract-canary.test.ts',
  'tests/v7-dispatch-funnel.test.ts',
  'tests/v7-confirm-consistency.test.ts',
  'tests/cq-3-merge-gate.test.ts',
  'tests/r2-02-quarantine.test.ts',
])

export const GATE_TEST_EXACT: ReadonlySet<string> = new Set([
  ...CORE_GATE_INVARIANT_TESTS,
  'tests/v8-seam1-golden-e2e.test.ts',
])

export const SCHEMA_AUTHORITY_TESTS: readonly string[] = Object.freeze([
  'tests/arch-b3-cascade.test.ts',
  'tests/confirmation-gate-parity.test.ts',
])

export const PROVIDER_REDACTION_TESTS: readonly string[] = Object.freeze([
  'tests/provider-stream.test.ts',
  'tests/t1-provider-stream.test.ts',
  'tests/r3-provider-scrub.test.ts',
  'tests/cq-13a-redaction-restore.test.ts',
  'tests/r2-ws11-redact-dos.test.ts',
  'tests/r2-ws7-provider-keys.test.ts',
])

export const MAX_KERNEL_QUARANTINE_DAYS = 14

/**
 * Generic triage bucket owners that are forbidden on kernel/critical quarantine entries.
 * Kernel/critical entries require a concrete named owner stream (e.g. `triage-kernel-<slug>`,
 * `r2-12-schema-auth`, `sys-q1-worker-pool`).
 */
export const GENERIC_TRIAGE_OWNER_RE =
  /^(?:(?:arch|ux|v\d+(?:-v\d+)?|misc|general|unknown|unassigned|todo|temp|tmp)-?triage|triage|unassigned|unknown|todo|none|n\/a)$/i

const CORE_GATE_SET = new Set<string>(CORE_GATE_INVARIANT_TESTS)
const SCHEMA_AUTHORITY_SET = new Set<string>(SCHEMA_AUTHORITY_TESTS)
const PROVIDER_REDACTION_SET = new Set<string>(PROVIDER_REDACTION_TESTS)

export function normalizeTestRelPath(relPath: string): string {
  return relPath.replace(/\\/g, '/').replace(/^\.\//, '')
}

export function isCoreGateInvariantTestFile(relPath: string): boolean {
  return CORE_GATE_SET.has(normalizeTestRelPath(relPath))
}

export function isKernelTestFile(relPath: string): boolean {
  return KERNEL_TEST_RE.test(normalizeTestRelPath(relPath))
}

export function isSchemaAuthorityTestFile(relPath: string): boolean {
  return SCHEMA_AUTHORITY_SET.has(normalizeTestRelPath(relPath))
}

export function isProviderRedactionTestFile(relPath: string): boolean {
  return PROVIDER_REDACTION_SET.has(normalizeTestRelPath(relPath))
}

export function isKernelOrCriticalTestFile(relPath: string): boolean {
  const norm = normalizeTestRelPath(relPath)
  return (
    CORE_GATE_SET.has(norm) ||
    KERNEL_TEST_RE.test(norm) ||
    SCHEMA_AUTHORITY_SET.has(norm) ||
    PROVIDER_REDACTION_SET.has(norm)
  )
}

export function isGenericTriageOwner(owner: string): boolean {
  const trimmed = owner.trim()
  if (!trimmed) return true
  return GENERIC_TRIAGE_OWNER_RE.test(trimmed)
}

// ============================================================================
// Semantic Test Header Tags (`R3-04`, `plans/claude_quality_3.md` §4)
// ============================================================================

export interface TestFileTags {
  kernel: boolean
  fixes: string[]
}

const MAX_TAG_HEADER_LINES = 40
const TAG_KERNEL_RE = /(?:^|[\s*])@kernel(?=$|[\s,;:])/
const TAG_FIXES_RE = /(?:^|[\s*])@fixes\s+([A-Za-z0-9._-]+(?:\s*,\s*[A-Za-z0-9._-]+)*)/g

function extractTagsFromCommentFragment(
  fragment: string,
  onKernel: () => void,
  fixes: Set<string>,
): void {
  if (TAG_KERNEL_RE.test(fragment)) {
    onKernel()
  }
  TAG_FIXES_RE.lastIndex = 0
  for (const m of fragment.matchAll(TAG_FIXES_RE)) {
    for (const rawId of m[1]!.split(',')) {
      const id = rawId.trim()
      if (id.length > 0) fixes.add(id)
    }
  }
}

/**
 * Parse semantic `// @kernel` and `// @fixes <ID>` tags from the leading comment header
 * of a test file (stops at the first non-comment code line or after 40 lines).
 */
export function parseTestFileTags(sourceText: string): TestFileTags {
  let kernel = false
  const fixes = new Set<string>()
  const lines = sourceText.split(/\r?\n/)
  const limit = Math.min(lines.length, MAX_TAG_HEADER_LINES)
  let inBlockComment = false

  for (let i = 0; i < limit; i += 1) {
    const trimmed = lines[i]!.trim()
    if (trimmed === '') continue
    if (i === 0 && trimmed.startsWith('#!')) continue
    if (inBlockComment) {
      const endIdx = trimmed.indexOf('*/')
      const fragment = endIdx >= 0 ? trimmed.slice(0, endIdx) : trimmed
      extractTagsFromCommentFragment(fragment, () => { kernel = true }, fixes)
      if (endIdx >= 0) inBlockComment = false
      continue
    }
    if (trimmed.startsWith('//')) {
      extractTagsFromCommentFragment(trimmed.slice(2), () => { kernel = true }, fixes)
      continue
    }
    if (trimmed.startsWith('/*')) {
      const afterOpen = trimmed.slice(2)
      const endIdx = afterOpen.indexOf('*/')
      const fragment = endIdx >= 0 ? afterOpen.slice(0, endIdx) : afterOpen
      extractTagsFromCommentFragment(fragment, () => { kernel = true }, fixes)
      if (endIdx < 0) inBlockComment = true
      continue
    }
    break
  }

  return { kernel, fixes: [...fixes] }
}

/**
 * Read leading semantic test tags (`@kernel`, `@fixes <ID>`) from a test file on disk.
 * Returns `{ kernel: false, fixes: [] }` if the file does not exist or cannot be read.
 */
export function readTestFileTags(filePath: string, rootDir: string = REPO_ROOT): TestFileTags {
  const resolved = isAbsolute(filePath) ? filePath : join(rootDir, normalizeTestRelPath(filePath))
  if (!existsSync(resolved)) return { kernel: false, fixes: [] }
  try {
    return parseTestFileTags(readFileSync(resolved, 'utf8'))
  } catch {
    return { kernel: false, fixes: [] }
  }
}

export function hasProtectedTestTag(tags: TestFileTags): boolean {
  return tags.kernel || tags.fixes.length > 0
}
