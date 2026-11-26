#!/usr/bin/env node
/**
 * Quarantine Debt Triage & Classification Tool (`R3-06`, plans/claude_quality_3.md §6).
 *
 * Read-only by default: classifies every entry in `tests/QUARANTINE.json` by:
 *   1. Suite tier (`core_gate`, `kernel`, `provider_redaction`, `schema_authority`, `tagged_kernel`, `non_kernel`)
 *   2. Failure / assertion class (`reason_only`, `verdict_fp_guard`, `verdict_tp_loss`,
 *      `environment_or_harness`, `non_kernel`) — using recorded `triageClass`, optional live
 *      hermetic TAP probing (`--probe`), or deterministic static classification
 *   3. Owner validity (generic triage rejection + live `ready`/`active` row resolution in
 *      `plans/STREAM-BACKLOG.md`)
 *   4. Expiry cliff concentration (date histogram, peak single-date share, expired entries)
 *
 * Emits a deterministic JSON (`--json`) or Markdown (`--markdown` / default) report.
 * Optional `--write-classes` writes `triageClass` onto kernel/critical entries without ever
 * increasing `maxQuarantinedCases` or any entry's `expires` date.
 *
 * Usage:
 *   node scripts/triage-quarantine.ts [--quarantine tests/QUARANTINE.json] [--backlog plans/STREAM-BACKLOG.md]
 *                                     [--root <dir>] [--now YYYY-MM-DD] [--probe] [--write-classes]
 *                                     [--json | --markdown] [--strict]
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  buildHermeticNodeTestArgs,
  buildHermeticTestEnv,
  prepareHermeticTestDir,
} from './runtime-profile.ts'
import {
  DEFAULT_STREAM_BACKLOG_REL,
  isCoreGateInvariantTestFile,
  isExplicitVerdictQuarantineEntry,
  isGenericTriageOwner,
  isKernelOrCriticalTestFile,
  isKernelTestFile,
  isKernelVerdictTriageClass,
  isLiveBacklogOwner,
  isProviderRedactionTestFile,
  isSchemaAuthorityTestFile,
  normalizeTestRelPath,
  readStreamBacklog,
  readTestFileTags,
  VALID_QUARANTINE_TRIAGE_CLASSES,
  type BacklogRow,
  type QuarantineAssertionKind,
  type QuarantineTriageClass,
} from './test-tiers.ts'

export type QuarantineSuiteTier =
  | 'core_gate'
  | 'kernel'
  | 'provider_redaction'
  | 'schema_authority'
  | 'tagged_kernel'
  | 'non_kernel'

export interface RawQuarantineEntry {
  file: string
  testName: string
  assertionLocation?: string
  ownerStream?: string
  owner?: string
  reason: string
  expires: string
  triageClass?: QuarantineTriageClass
  assertionKind?: QuarantineAssertionKind
}

export interface RawQuarantineFile {
  version: number
  maxQuarantinedCases: number
  maxKernelVerdictQuarantinedCases?: number
  entries: RawQuarantineEntry[]
}

export interface TapFailureDetail {
  name: string
  status: 'pass' | 'fail' | 'skipped'
  operator: string
  actual: string
  expected: string
  errorLine: string
}

export interface TriagedQuarantineEntry {
  file: string
  testName: string
  assertionLocation: string | null
  tier: QuarantineSuiteTier
  isKernelOrCritical: boolean
  triageClass: QuarantineTriageClass
  classificationSource: 'recorded' | 'probed' | 'static'
  assertionScope: 'verdict' | 'prose' | 'harness'
  explicitVerdictTag: boolean
  ownerStream: string
  ownerValid: boolean
  ownerIssue: string | null
  expires: string
  daysUntilExpiry: number | null
  expired: boolean
  reason: string
  probeDetail?: {
    status: TapFailureDetail['status'] | 'missing'
    operator: string
    errorLine: string
  }
}

export interface ExpiryCliffSummary {
  totalEntries: number
  histogram: Record<string, number>
  uniqueDates: number
  peakDate: string | null
  peakCount: number
  peakShare: number
  concentrated: boolean
  earliestExpiry: string | null
  latestExpiry: string | null
  expiredCount: number
}

export interface QuarantineTriageReport {
  ok: boolean
  quarantinePath: string
  backlogPath: string
  nowDate: string
  probed: boolean
  totalEntries: number
  maxQuarantinedCases: number
  maxKernelVerdictQuarantinedCases: number | null
  uniqueFiles: number
  kernelOrCriticalCount: number
  nonKernelCount: number
  countsByTier: Record<QuarantineSuiteTier, number>
  countsByTriageClass: Record<QuarantineTriageClass, number>
  invalidOwnerCount: number
  explicitVerdictCount: number
  expiryCliffAll: ExpiryCliffSummary
  expiryCliffKernel: ExpiryCliffSummary
  issues: string[]
  entries: TriagedQuarantineEntry[]
}

export interface TriageQuarantineOptions {
  rootDir?: string
  quarantinePath?: string
  backlogPath?: string
  nowDate?: string
  probe?: boolean
}

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const DEFAULT_QUARANTINE_REL = 'tests/QUARANTINE.json'

function isValidIsoDate(s: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false
  const [y, m, d] = s.split('-').map(Number) as [number, number, number]
  const dt = new Date(Date.UTC(y, m - 1, d))
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d
}

function diffCalendarDays(laterIso: string, earlierIso: string): number {
  const [y1, m1, d1] = laterIso.split('-').map(Number) as [number, number, number]
  const [y2, m2, d2] = earlierIso.split('-').map(Number) as [number, number, number]
  return Math.round((Date.UTC(y1, m1 - 1, d1) - Date.UTC(y2, m2 - 1, d2)) / 86_400_000)
}

export function classifySuiteTier(file: string, rootDir: string = REPO_ROOT): QuarantineSuiteTier {
  const norm = normalizeTestRelPath(file)
  if (isCoreGateInvariantTestFile(norm)) return 'core_gate'
  if (isKernelTestFile(norm)) return 'kernel'
  if (isProviderRedactionTestFile(norm)) return 'provider_redaction'
  if (isSchemaAuthorityTestFile(norm)) return 'schema_authority'
  if (readTestFileTags(norm, rootDir).kernel) return 'tagged_kernel'
  return 'non_kernel'
}

/**
 * Parse TAP leaf cases with structured failure metadata (`operator`, `actual`, `expected`, first error line).
 */
export function parseTapFailureDetails(tapText: string): TapFailureDetail[] {
  const lines = tapText.split(/\r?\n/)
  const out: TapFailureDetail[] = []
  const stack: string[] = []
  let i = 0
  while (i < lines.length) {
    const subM = /^((?:    )*)# Subtest: (.*)$/.exec(lines[i]!)
    if (subM) {
      const depth = subM[1]!.length / 4
      stack.length = depth
      stack[depth] = subM[2]!.trim()
      i += 1
      continue
    }
    const resM = /^((?:    )*)(not ok|ok) \d+(?: - (.*))?$/.exec(lines[i]!)
    if (resM) {
      const depth = resM[1]!.length / 4
      const ok = resM[2] === 'ok'
      const rawLabel = resM[3] ?? ''
      const skipped = /\s+#\s*(?:SKIP|TODO)\b/i.test(rawLabel)
      const label = rawLabel.replace(/\s+#\s*(?:SKIP|TODO).*$/i, '').trim()
      stack.length = depth
      const fullName = [...stack, label].filter(Boolean).join(' > ')
      let type = 'test'
      let failureType = ''
      let operator = ''
      let actual = ''
      let expected = ''
      let errorLine = ''
      if (i + 1 < lines.length && /^(\s+)---$/.test(lines[i + 1]!)) {
        const ind = /^(\s+)---$/.exec(lines[i + 1]!)![1]!
        i += 2
        let inErr = false
        while (i < lines.length && lines[i] !== `${ind}...`) {
          const y = lines[i]!
          if (inErr) {
            if (y.startsWith(`${ind}  `) || y.trim() === '') {
              if (!errorLine && y.trim()) errorLine = y.trim()
              i += 1
              continue
            }
            inErr = false
          }
          if (y.startsWith(ind)) {
            const tr = y.slice(ind.length)
            let m: RegExpExecArray | null
            if ((m = /^type:\s*'?([^']+)'?$/.exec(tr))) type = m[1]!.trim()
            else if ((m = /^failureType:\s*'?([^']+)'?$/.exec(tr))) failureType = m[1]!.trim()
            else if ((m = /^operator:\s*'?([^']+)'?$/.exec(tr))) operator = m[1]!.trim()
            else if ((m = /^actual:\s*(.*)$/.exec(tr))) actual = m[1]!.trim().slice(0, 120)
            else if ((m = /^expected:\s*(.*)$/.exec(tr))) expected = m[1]!.trim().slice(0, 120)
            else if ((m = /^error:\s*(.*)$/.exec(tr))) {
              const v = m[1]!.trim()
              if (v === '|-' || v === '|' || v === '>-' || v === '>') inErr = true
              else errorLine = v.replace(/^['"]|['"]$/g, '').trim().slice(0, 160)
            }
          }
          i += 1
        }
      }
      if (type !== 'suite' && failureType !== 'subtestsFailed') {
        out.push({
          name: fullName,
          status: skipped ? 'skipped' : ok ? 'pass' : 'fail',
          operator,
          actual,
          expected,
          errorLine: errorLine.slice(0, 160),
        })
      }
    }
    i += 1
  }
  return out
}

const HARNESS_HINT_RE =
  /(?:NODE_ENV=test|model_error|scheme_blocked|decomposed below \d|LOC \(must be|TOOL_DESCRIPTION|agent-prompts|prompt)/i
const NEGATIVE_GUARD_NAME_RE =
  /\b(?:reject|rejects|rejected|do not confirm|fails? closed|cannot|forbid|blocks|dismisses|names a missing)\b/i
const REASON_CODE_MISMATCH_RE =
  /^'(?:transcript_integrity|terminal_impact|missing_signature_digest_binding|terminal_impact_unproven|replay_mode|edge_binding|timing_arm|boolean_arm)/i

/**
 * Classify a live TAP failure for a kernel/critical entry into one of:
 *   - `environment_or_harness` (LOC ceiling, prompt prose, NODE_ENV guard, loopback model harness)
 *   - `reason_only` (rejection still intact; failed on reason-prose regex, missing-arm label, or error-stage code)
 *   - `verdict_fp_guard` (negative/FP guard unexpectedly confirmed: expected `false`, got `true`)
 *   - `verdict_tp_loss` (positive/TP case failed to confirm: expected `true`/`1`, got `false`/`0`)
 */
export function classifyTapFailure(
  testName: string,
  detail: TapFailureDetail,
): Exclude<QuarantineTriageClass, 'non_kernel'> {
  const combined = `${testName} ${detail.errorLine}`
  if (HARNESS_HINT_RE.test(combined)) {
    return 'environment_or_harness'
  }
  if (detail.operator === 'match' || detail.operator === 'doesNotMatch') {
    return 'reason_only'
  }
  if (
    detail.expected === 'false' &&
    detail.actual === 'true'
  ) {
    return 'verdict_fp_guard'
  }
  if (
    NEGATIVE_GUARD_NAME_RE.test(testName) &&
    (REASON_CODE_MISMATCH_RE.test(detail.expected) ||
      REASON_CODE_MISMATCH_RE.test(detail.actual) ||
      /^(?:timing_arm|boolean_arm)\b/.test(detail.errorLine))
  ) {
    return 'reason_only'
  }
  if (
    (detail.expected === 'true' && detail.actual === 'false') ||
    (detail.expected === '1' && detail.actual === '0') ||
    detail.operator === 'strictEqual'
  ) {
    return 'verdict_tp_loss'
  }
  return NEGATIVE_GUARD_NAME_RE.test(testName) ? 'reason_only' : 'verdict_tp_loss'
}

/**
 * Deterministic static fallback classification when an entry has no recorded `triageClass`
 * and `--probe` was not requested.
 */
export function classifyQuarantineEntryStatic(
  entry: RawQuarantineEntry,
  isKernelOrCritical: boolean,
): QuarantineTriageClass {
  if (!isKernelOrCritical) return 'non_kernel'
  if (HARNESS_HINT_RE.test(`${entry.testName} ${entry.reason}`)) {
    return 'environment_or_harness'
  }
  if (entry.assertionKind === 'prose') return 'reason_only'
  if (entry.assertionKind === 'harness') return 'environment_or_harness'
  if (NEGATIVE_GUARD_NAME_RE.test(entry.testName) && !/\bconfirms?\b/i.test(entry.testName)) {
    return 'reason_only'
  }
  return 'verdict_tp_loss'
}

export function buildExpiryCliffSummary(
  entries: ReadonlyArray<{ expires: string; expired: boolean }>,
): ExpiryCliffSummary {
  const counts = new Map<string, number>()
  let expiredCount = 0
  for (const e of entries) {
    if (e.expired) expiredCount += 1
    if (!e.expires) continue
    counts.set(e.expires, (counts.get(e.expires) ?? 0) + 1)
  }
  const sortedDates = [...counts.keys()].sort()
  const histogram: Record<string, number> = {}
  let peakDate: string | null = null
  let peakCount = 0
  for (const d of sortedDates) {
    const c = counts.get(d)!
    histogram[d] = c
    if (c > peakCount) {
      peakCount = c
      peakDate = d
    }
  }
  const totalEntries = entries.length
  const peakShare = totalEntries > 0 ? Number((peakCount / totalEntries).toFixed(4)) : 0
  const concentrated = totalEntries >= 4 && peakShare > 0.5
  return {
    totalEntries,
    histogram,
    uniqueDates: sortedDates.length,
    peakDate,
    peakCount,
    peakShare,
    concentrated,
    earliestExpiry: sortedDates[0] ?? null,
    latestExpiry: sortedDates[sortedDates.length - 1] ?? null,
    expiredCount,
  }
}

function probeKernelFiles(
  files: readonly string[],
  rootDir: string,
): Map<string, Map<string, TapFailureDetail>> {
  const byFile = new Map<string, Map<string, TapFailureDetail>>()
  for (const file of [...files].sort()) {
    const absFile = join(rootDir, file)
    if (!existsSync(absFile)) continue
    const sandboxDir = prepareHermeticTestDir(undefined, 'triage-probe-')
    let tap = ''
    try {
      const args = buildHermeticNodeTestArgs(absFile, ['--test-timeout=25000', '--test-force-exit'])
      try {
        tap = execFileSync(process.execPath, args, {
          cwd: rootDir,
          env: buildHermeticTestEnv(sandboxDir),
          encoding: 'utf8',
          maxBuffer: 8 * 1024 * 1024,
        })
      } catch (err) {
        const e = err as { stdout?: unknown }
        tap = String(e.stdout ?? '')
      }
    } finally {
      rmSync(sandboxDir, { recursive: true, force: true })
    }
    const map = new Map<string, TapFailureDetail>()
    for (const detail of parseTapFailureDetails(tap)) {
      map.set(detail.name, detail)
    }
    byFile.set(file, map)
  }
  return byFile
}

export function triageQuarantine(options: TriageQuarantineOptions = {}): QuarantineTriageReport {
  const rootDir = resolve(options.rootDir ?? REPO_ROOT)
  const quarantineRel = options.quarantinePath ?? DEFAULT_QUARANTINE_REL
  const backlogRel = options.backlogPath ?? DEFAULT_STREAM_BACKLOG_REL
  const absQuarantine = isAbsolute(quarantineRel) ? quarantineRel : join(rootDir, quarantineRel)
  const absBacklog = isAbsolute(backlogRel) ? backlogRel : join(rootDir, backlogRel)
  const nowDate = (options.nowDate ?? '').trim() || new Date().toISOString().slice(0, 10)
  const probe = Boolean(options.probe)

  const parsed = JSON.parse(readFileSync(absQuarantine, 'utf8')) as RawQuarantineFile
  const backlogRows: BacklogRow[] = existsSync(absBacklog) ? readStreamBacklog(absBacklog, rootDir) : []
  const rawEntries = Array.isArray(parsed.entries) ? parsed.entries : []

  const kernelFilesToProbe = new Set<string>()
  if (probe) {
    for (const e of rawEntries) {
      const normFile = normalizeTestRelPath(e.file ?? '')
      const tier = classifySuiteTier(normFile, rootDir)
      if (tier !== 'non_kernel') kernelFilesToProbe.add(normFile)
    }
  }
  const probedMap = probe ? probeKernelFiles([...kernelFilesToProbe], rootDir) : new Map()

  const countsByTier: Record<QuarantineSuiteTier, number> = {
    core_gate: 0,
    kernel: 0,
    provider_redaction: 0,
    schema_authority: 0,
    tagged_kernel: 0,
    non_kernel: 0,
  }
  const countsByTriageClass: Record<QuarantineTriageClass, number> = {
    reason_only: 0,
    verdict_fp_guard: 0,
    verdict_tp_loss: 0,
    environment_or_harness: 0,
    non_kernel: 0,
  }

  const issues: string[] = []
  const uniqueFileSet = new Set<string>()
  const entries: TriagedQuarantineEntry[] = []

  const sortedRaw = [...rawEntries].sort((a, b) => {
    const fc = normalizeTestRelPath(a.file ?? '').localeCompare(normalizeTestRelPath(b.file ?? ''))
    return fc !== 0 ? fc : (a.testName ?? '').localeCompare(b.testName ?? '')
  })

  for (const raw of sortedRaw) {
    const file = normalizeTestRelPath(raw.file ?? '')
    const testName = (raw.testName ?? '').trim()
    const ownerStream = (raw.ownerStream ?? raw.owner ?? '').trim()
    const expires = (raw.expires ?? '').trim()
    const reason = (raw.reason ?? '').trim()
    uniqueFileSet.add(file)

    const tier = classifySuiteTier(file, rootDir)
    const isKernelOrCritical = tier !== 'non_kernel' || isKernelOrCriticalTestFile(file)
    countsByTier[tier] += 1

    const explicitVerdictTag = isExplicitVerdictQuarantineEntry({
      testName,
      assertionKind: raw.assertionKind,
    })

    let triageClass: QuarantineTriageClass
    let classificationSource: 'recorded' | 'probed' | 'static'
    let probeDetail: TriagedQuarantineEntry['probeDetail']

    const probedFile = probedMap.get(file)
    if (probe && isKernelOrCritical && probedFile) {
      const hit = probedFile.get(testName)
      if (hit) {
        triageClass = hit.status === 'fail'
          ? classifyTapFailure(testName, hit)
          : (raw.triageClass && VALID_QUARANTINE_TRIAGE_CLASSES.has(raw.triageClass)
              ? raw.triageClass
              : classifyQuarantineEntryStatic(raw, isKernelOrCritical))
        classificationSource = 'probed'
        probeDetail = { status: hit.status, operator: hit.operator, errorLine: hit.errorLine }
      } else {
        triageClass = raw.triageClass && VALID_QUARANTINE_TRIAGE_CLASSES.has(raw.triageClass)
          ? raw.triageClass
          : classifyQuarantineEntryStatic(raw, isKernelOrCritical)
        classificationSource = raw.triageClass ? 'recorded' : 'static'
        probeDetail = { status: 'missing', operator: '', errorLine: 'case not found in TAP output' }
      }
    } else if (raw.triageClass && VALID_QUARANTINE_TRIAGE_CLASSES.has(raw.triageClass)) {
      triageClass = raw.triageClass
      classificationSource = 'recorded'
    } else {
      triageClass = classifyQuarantineEntryStatic(raw, isKernelOrCritical)
      classificationSource = 'static'
    }
    countsByTriageClass[triageClass] += 1

    const assertionScope: 'verdict' | 'prose' | 'harness' =
      explicitVerdictTag || isKernelVerdictTriageClass(triageClass)
        ? 'verdict'
        : triageClass === 'environment_or_harness'
          ? 'harness'
          : 'prose'

    let ownerValid = true
    let ownerIssue: string | null = null
    if (!ownerStream) {
      ownerValid = false
      ownerIssue = 'missing ownerStream'
    } else if (isKernelOrCritical) {
      if (isGenericTriageOwner(ownerStream)) {
        ownerValid = false
        ownerIssue = `generic triage owner '${ownerStream}' forbidden for kernel/critical entry`
      } else if (!isLiveBacklogOwner(ownerStream, backlogRows)) {
        ownerValid = false
        ownerIssue = `ownerStream '${ownerStream}' has no live (ready/active) row in ${backlogRel}`
      }
    }

    const daysUntilExpiry =
      isValidIsoDate(expires) && isValidIsoDate(nowDate)
        ? diffCalendarDays(expires, nowDate)
        : null
    const expired = daysUntilExpiry !== null && daysUntilExpiry < 0

    if (!ownerValid) {
      issues.push(`${file} :: ${testName} — ${ownerIssue}`)
    }
    if (expired) {
      issues.push(`${file} :: ${testName} — expired (${expires} < ${nowDate})`)
    }
    if (isKernelOrCritical && explicitVerdictTag) {
      issues.push(`${file} :: ${testName} — explicit kernel verdict assertion cannot be quarantined`)
    }

    entries.push({
      file,
      testName,
      assertionLocation: raw.assertionLocation?.trim() || null,
      tier,
      isKernelOrCritical,
      triageClass,
      classificationSource,
      assertionScope,
      explicitVerdictTag,
      ownerStream,
      ownerValid,
      ownerIssue,
      expires,
      daysUntilExpiry,
      expired,
      reason,
      ...(probeDetail ? { probeDetail } : {}),
    })
  }

  const kernelEntries = entries.filter(e => e.isKernelOrCritical)
  const expiryCliffAll = buildExpiryCliffSummary(entries)
  const expiryCliffKernel = buildExpiryCliffSummary(kernelEntries)
  if (expiryCliffKernel.concentrated) {
    issues.push(
      `kernel expiry cliff concentrated: ${expiryCliffKernel.peakCount}/${expiryCliffKernel.totalEntries} (${Math.round(expiryCliffKernel.peakShare * 100)}%) expire on ${expiryCliffKernel.peakDate}`,
    )
  }

  const invalidOwnerCount = entries.filter(e => !e.ownerValid).length
  const explicitVerdictCount = kernelEntries.filter(e => e.explicitVerdictTag).length

  return {
    ok: invalidOwnerCount === 0 && expiryCliffAll.expiredCount === 0 && explicitVerdictCount === 0,
    quarantinePath: quarantineRel,
    backlogPath: backlogRel,
    nowDate,
    probed: probe,
    totalEntries: entries.length,
    maxQuarantinedCases: parsed.maxQuarantinedCases,
    maxKernelVerdictQuarantinedCases: parsed.maxKernelVerdictQuarantinedCases ?? null,
    uniqueFiles: uniqueFileSet.size,
    kernelOrCriticalCount: kernelEntries.length,
    nonKernelCount: entries.length - kernelEntries.length,
    countsByTier,
    countsByTriageClass,
    invalidOwnerCount,
    explicitVerdictCount,
    expiryCliffAll,
    expiryCliffKernel,
    issues,
    entries,
  }
}

export function renderTriageMarkdown(report: QuarantineTriageReport): string {
  const lines: string[] = []
  lines.push(`# Quarantine Triage Report (${report.nowDate})`)
  lines.push('')
  lines.push(`- **Status:** ${report.ok ? 'OK' : 'ISSUES_FOUND'}`)
  lines.push(`- **Quarantine file:** \`${report.quarantinePath}\` (${report.totalEntries}/${report.maxQuarantinedCases} cases across ${report.uniqueFiles} files)`)
  lines.push(`- **Kernel/critical entries:** ${report.kernelOrCriticalCount} (non-kernel: ${report.nonKernelCount})`)
  if (report.maxKernelVerdictQuarantinedCases !== null) {
    const verdictCount = report.countsByTriageClass.verdict_tp_loss + report.countsByTriageClass.verdict_fp_guard
    lines.push(`- **Legacy kernel verdict ratchet:** ${verdictCount}/${report.maxKernelVerdictQuarantinedCases}`)
  }
  lines.push(`- **Invalid owners:** ${report.invalidOwnerCount} | **Expired:** ${report.expiryCliffAll.expiredCount} | **Explicit verdict violations:** ${report.explicitVerdictCount}`)
  lines.push(
    `- **Kernel expiry cliff:** peak \`${report.expiryCliffKernel.peakDate ?? 'n/a'}\` (${report.expiryCliffKernel.peakCount}/${report.expiryCliffKernel.totalEntries}, ${Math.round(report.expiryCliffKernel.peakShare * 100)}%, concentrated=${report.expiryCliffKernel.concentrated})`,
  )
  lines.push('')
  lines.push('## Breakdown by Triage Class')
  lines.push('')
  lines.push('| Class | Count |')
  lines.push('|---|---|')
  for (const cls of ['reason_only', 'verdict_fp_guard', 'verdict_tp_loss', 'environment_or_harness', 'non_kernel'] as const) {
    lines.push(`| \`${cls}\` | ${report.countsByTriageClass[cls]} |`)
  }
  lines.push('')
  lines.push('## Kernel/Critical Expiry Distribution')
  lines.push('')
  lines.push('| Expiry Date | Cases |')
  lines.push('|---|---|')
  for (const [date, count] of Object.entries(report.expiryCliffKernel.histogram)) {
    lines.push(`| ${date} | ${count} |`)
  }
  if (Object.keys(report.expiryCliffKernel.histogram).length === 0) {
    lines.push('| (none) | 0 |')
  }
  lines.push('')
  lines.push('## Kernel/Critical Files Summary')
  lines.push('')
  lines.push('| File | Owner | Valid | Expiry | reason_only | verdict_fp_guard | verdict_tp_loss | harness |')
  lines.push('|---|---|---|---|---|---|---|---|')
  const byFile = new Map<string, TriagedQuarantineEntry[]>()
  for (const e of report.entries) {
    if (!e.isKernelOrCritical) continue
    const list = byFile.get(e.file) ?? []
    list.push(e)
    byFile.set(e.file, list)
  }
  for (const [file, list] of [...byFile.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const owners = [...new Set(list.map(x => x.ownerStream))].join(', ')
    const valid = list.every(x => x.ownerValid) ? 'yes' : 'NO'
    const expiries = [...new Set(list.map(x => x.expires))].sort().join(', ')
    const cReason = list.filter(x => x.triageClass === 'reason_only').length
    const cFp = list.filter(x => x.triageClass === 'verdict_fp_guard').length
    const cTp = list.filter(x => x.triageClass === 'verdict_tp_loss').length
    const cHar = list.filter(x => x.triageClass === 'environment_or_harness').length
    lines.push(`| \`${file}\` | \`${owners}\` | ${valid} | ${expiries} | ${cReason} | ${cFp} | ${cTp} | ${cHar} |`)
  }
  if (report.issues.length > 0) {
    lines.push('')
    lines.push('## Issues')
    lines.push('')
    for (const issue of report.issues) {
      lines.push(`- ${issue}`)
    }
  }
  return `${lines.join('\n')}\n`
}

function writeTriageClassesToQuarantine(
  report: QuarantineTriageReport,
  rootDir: string,
): number {
  const absQ = isAbsolute(report.quarantinePath)
    ? report.quarantinePath
    : join(rootDir, report.quarantinePath)
  const parsed = JSON.parse(readFileSync(absQ, 'utf8')) as RawQuarantineFile
  const byKey = new Map<string, TriagedQuarantineEntry>()
  for (const e of report.entries) {
    byKey.set(`${e.file}\0${e.testName}`, e)
  }
  let updated = 0
  for (const raw of parsed.entries) {
    const key = `${normalizeTestRelPath(raw.file)}\0${raw.testName.trim()}`
    const triaged = byKey.get(key)
    if (!triaged || !triaged.isKernelOrCritical) continue
    if (raw.triageClass !== triaged.triageClass) {
      raw.triageClass = triaged.triageClass
      updated += 1
    }
  }
  writeFileSync(absQ, `${JSON.stringify(parsed, null, 2)}\n`, 'utf8')
  return updated
}

function runCli(): void {
  const args = process.argv.slice(2)
  let rootDir = REPO_ROOT
  let quarantinePath = DEFAULT_QUARANTINE_REL
  let backlogPath = DEFAULT_STREAM_BACKLOG_REL
  let nowDate: string | undefined
  let probe = false
  let writeClasses = false
  let format: 'markdown' | 'json' = 'markdown'
  let strict = false

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!
    if (arg === '--root' && args[i + 1]) {
      rootDir = resolve(args[++i]!)
    } else if (arg === '--quarantine' && args[i + 1]) {
      quarantinePath = args[++i]!
    } else if (arg === '--backlog' && args[i + 1]) {
      backlogPath = args[++i]!
    } else if (arg === '--now' && args[i + 1]) {
      nowDate = args[++i]!
    } else if (arg === '--probe') {
      probe = true
    } else if (arg === '--write-classes') {
      writeClasses = true
    } else if (arg === '--json') {
      format = 'json'
    } else if (arg === '--markdown' || arg === '--md') {
      format = 'markdown'
    } else if (arg === '--strict') {
      strict = true
    } else if (arg === '-h' || arg === '--help') {
      console.log(
        'Usage: node scripts/triage-quarantine.ts [--quarantine <path>] [--backlog <path>] [--root <dir>] [--now YYYY-MM-DD] [--probe] [--write-classes] [--json|--markdown] [--strict]',
      )
      process.exit(0)
    } else {
      console.error(`Unknown option: ${arg}`)
      process.exit(2)
    }
  }

  const report = triageQuarantine({ rootDir, quarantinePath, backlogPath, nowDate, probe })
  if (writeClasses) {
    const updated = writeTriageClassesToQuarantine(report, rootDir)
    if (format === 'markdown') {
      console.error(`Updated triageClass on ${updated} kernel/critical quarantine entries in ${quarantinePath}`)
    }
  }

  if (format === 'json') {
    console.log(JSON.stringify(report, null, 2))
  } else {
    process.stdout.write(renderTriageMarkdown(report))
  }

  if (strict && !report.ok) {
    process.exit(1)
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  runCli()
}
