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
  'tests/r3-06-quarantine.test.ts',
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

// ============================================================================
// Quarantine Backlog Owner & Verdict-Split Validation (`R3-06`, §6)
// ============================================================================

export type BacklogRowStatus = 'ready' | 'active' | 'blocked' | 'completed'

export interface BacklogRow {
  id: string
  status: BacklogRowStatus
  lease: string
  stream: string
  line: number
  checked: boolean
}

export type QuarantineTriageClass =
  | 'reason_only'
  | 'verdict_fp_guard'
  | 'verdict_tp_loss'
  | 'environment_or_harness'
  | 'non_kernel'

export type QuarantineAssertionKind = 'prose' | 'verdict' | 'harness'

export const VALID_QUARANTINE_TRIAGE_CLASSES: ReadonlySet<QuarantineTriageClass> = new Set<QuarantineTriageClass>([
  'reason_only',
  'verdict_fp_guard',
  'verdict_tp_loss',
  'environment_or_harness',
  'non_kernel',
])

export const VALID_QUARANTINE_ASSERTION_KINDS: ReadonlySet<QuarantineAssertionKind> = new Set<QuarantineAssertionKind>([
  'prose',
  'verdict',
  'harness',
])

export const KERNEL_VERDICT_TRIAGE_CLASSES: ReadonlySet<QuarantineTriageClass> = new Set<QuarantineTriageClass>([
  'verdict_fp_guard',
  'verdict_tp_loss',
])

/**
 * Explicit verdict-scoped test names (`[verdict]`, `verdict:`, `@verdict`) that can NEVER
 * be quarantined inside a kernel/critical suite.
 */
export const EXPLICIT_VERDICT_TEST_NAME_RE = /(?:\[verdict\]|\bverdict\s*:|@verdict\b)/i

export const DEFAULT_STREAM_BACKLOG_REL = 'plans/STREAM-BACKLOG.md'

const BACKLOG_ROW_RE = /^\s*-\s*\[( |x|X)\]\s*`([^`]+)`(.*)$/

function stripBackticks(value: string): string {
  const trimmed = value.trim()
  if (trimmed.startsWith('`') && trimmed.endsWith('`') && trimmed.length >= 2) {
    return trimmed.slice(1, -1).trim()
  }
  return trimmed
}

/**
 * Parse task rows from `plans/STREAM-BACKLOG.md`.
 * Format:
 *   `- [ ] \`<task-id>\` — <desc> | status: ready|active|blocked | lease: <files> | deps: <ids> | stream: <branch or ->`
 */
export function parseStreamBacklog(markdown: string): BacklogRow[] {
  const rows: BacklogRow[] = []
  const lines = markdown.split(/\r?\n/)
  for (let i = 0; i < lines.length; i += 1) {
    const m = BACKLOG_ROW_RE.exec(lines[i]!)
    if (!m) continue
    const checked = m[1]!.toLowerCase() === 'x'
    const id = m[2]!.trim()
    if (!id) continue
    const tail = m[3] ?? ''
    const statusMatch = /\|\s*status:\s*(ready|active|blocked|completed)\b/i.exec(tail)
    const leaseMatch = /\|\s*lease:\s*([^|]+)/i.exec(tail)
    const streamMatch = /\|\s*stream:\s*([^|]+)/i.exec(tail)
    const status: BacklogRowStatus = checked
      ? 'completed'
      : ((statusMatch?.[1]?.toLowerCase() as BacklogRowStatus | undefined) ?? 'ready')
    const lease = leaseMatch ? leaseMatch[1]!.trim() : ''
    const stream = streamMatch ? stripBackticks(streamMatch[1]!) : ''
    rows.push({
      id,
      status,
      lease,
      stream: stream === '-' ? '' : stream,
      line: i + 1,
      checked,
    })
  }
  return rows
}

/**
 * Read and parse `plans/STREAM-BACKLOG.md` (or an explicit backlog file path).
 */
export function readStreamBacklog(
  backlogPath: string = DEFAULT_STREAM_BACKLOG_REL,
  rootDir: string = REPO_ROOT,
): BacklogRow[] {
  const resolved = isAbsolute(backlogPath) ? backlogPath : join(rootDir, backlogPath)
  if (!existsSync(resolved)) return []
  try {
    return parseStreamBacklog(readFileSync(resolved, 'utf8'))
  } catch {
    return []
  }
}

/**
 * Return the set of live (`ready` or `active`, unchecked) owner IDs / stream slugs from `STREAM-BACKLOG.md`.
 */
export function getLiveBacklogOwners(rows: readonly BacklogRow[]): Set<string> {
  const live = new Set<string>()
  for (const row of rows) {
    if (row.checked) continue
    if (row.status !== 'ready' && row.status !== 'active') continue
    live.add(row.id)
    if (row.stream && row.stream !== '-') {
      live.add(row.stream)
      const shortStream = row.stream.replace(/^(?:agents|swarm)\//, '')
      if (shortStream) live.add(shortStream)
    }
  }
  return live
}

/**
 * Check whether an `ownerStream` resolves to a live (`ready` or `active`) row in `plans/STREAM-BACKLOG.md`.
 */
export function isLiveBacklogOwner(owner: string, rows: readonly BacklogRow[]): boolean {
  const trimmed = owner.trim()
  if (!trimmed || isGenericTriageOwner(trimmed)) return false
  return getLiveBacklogOwners(rows).has(trimmed)
}

/**
 * Classify whether a test file is kernel/critical by path rules OR leading `@kernel` comment tag.
 */
export function isKernelOrCriticalTestFileWithTags(
  relPath: string,
  rootDir: string = REPO_ROOT,
): boolean {
  if (isKernelOrCriticalTestFile(relPath)) return true
  return readTestFileTags(relPath, rootDir).kernel
}

/**
 * True when a quarantine entry explicitly targets a verdict assertion (unconditionally unquarantinable
 * in kernel/critical suites).
 */
export function isExplicitVerdictQuarantineEntry(entry: {
  testName?: string
  assertionKind?: string
}): boolean {
  if (entry.assertionKind === 'verdict') return true
  return typeof entry.testName === 'string' && EXPLICIT_VERDICT_TEST_NAME_RE.test(entry.testName)
}

export function isKernelVerdictTriageClass(triageClass: string | undefined): boolean {
  return typeof triageClass === 'string' && KERNEL_VERDICT_TRIAGE_CLASSES.has(triageClass as QuarantineTriageClass)
}
