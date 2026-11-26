#!/usr/bin/env node
/**
 * Regenerates verification metric tables from `benchmarks/results/ledger.jsonl`.
 *
 * Fail-closed invariant (plans/claude_quality.md Item #2):
 *  - FAILS with `MixedLedgerVersionError` (CLI exit 1) if a single rendered table mixes
 *    incompatible `benchmarkVersion` or `effectiveConfigHash` values.
 *  - Refuses `status === 'INVALID'` or `reportable === false` rows unless explicitly filtered out.
 *  - Every rendered table carries its exact `benchmarkVersion` and `effectiveConfigHash` stamp.
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  DEFAULT_LEDGER_PATH,
  readLedgerRows,
  type BenchmarkSuiteName,
  type LedgerRow,
} from './bench-ledger.ts'

export class MixedLedgerVersionError extends Error {
  readonly kind: 'benchmarkVersion' | 'effectiveConfigHash' | 'invalidRow' | 'nonReportableRow'
  readonly values: string[]
  constructor(
    kind: 'benchmarkVersion' | 'effectiveConfigHash' | 'invalidRow' | 'nonReportableRow',
    message: string,
    values: string[],
  ) {
    super(message)
    this.name = 'MixedLedgerVersionError'
    this.kind = kind
    this.values = values
  }
}

export interface TableValidationResult {
  benchmarkVersion: string | null
  effectiveConfigHash: string | null
  rows: LedgerRow[]
  certifyingAll: boolean
}

/**
 * Validate that every row intended for a single verification table shares one `benchmarkVersion`
 * and one `effectiveConfigHash` (and that no row is INVALID or non-reportable).
 */
export function validateTableRows(
  rows: readonly LedgerRow[],
  opts: { tableName?: string; allowNonReportable?: boolean } = {},
): TableValidationResult {
  const label = opts.tableName ? `table '${opts.tableName}'` : 'verification table'
  if (rows.length === 0) {
    return { benchmarkVersion: null, effectiveConfigHash: null, rows: [], certifyingAll: false }
  }

  const invalid = rows.filter(r => r.status === 'INVALID')
  if (invalid.length > 0) {
    throw new MixedLedgerVersionError(
      'invalidRow',
      `${label} contains ${invalid.length} INVALID row(s): ${invalid.map(r => `${r.app}@${r.seed}`).join(', ')}`,
      invalid.map(r => `${r.app}@${r.seed}`),
    )
  }

  if (!opts.allowNonReportable) {
    const nonReportable = rows.filter(r => r.reportable === false)
    if (nonReportable.length > 0) {
      throw new MixedLedgerVersionError(
        'nonReportableRow',
        `${label} contains ${nonReportable.length} non-reportable row(s) (e.g. wordlistOn=true)`,
        nonReportable.map(r => `${r.app}@${r.seed}`),
      )
    }
  }

  const versions = [...new Set(rows.map(r => r.benchmarkVersion))].sort()
  if (versions.length > 1) {
    throw new MixedLedgerVersionError(
      'benchmarkVersion',
      `${label} mixes incompatible benchmarkVersion values: ${versions.map(v => v.slice(0, 12)).join(' vs ')}`,
      versions,
    )
  }

  const configs = [...new Set(rows.map(r => r.effectiveConfigHash))].sort()
  if (configs.length > 1) {
    throw new MixedLedgerVersionError(
      'effectiveConfigHash',
      `${label} mixes incompatible effectiveConfigHash values: ${configs.map(c => c.slice(0, 12)).join(' vs ')}`,
      configs,
    )
  }

  return {
    benchmarkVersion: versions[0]!,
    effectiveConfigHash: configs[0]!,
    rows: [...rows],
    certifyingAll: rows.every(r => r.certifying),
  }
}

function fmtPct(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return 'n/a'
  return `${(v * 100).toFixed(1)}%`
}

function fmtUsd(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return 'n/a'
  return `$${v.toFixed(3)}`
}

/**
 * Render one Markdown metric table from a homogeneous set of ledger rows.
 * Throws `MixedLedgerVersionError` if the rows mix `benchmarkVersion` or `effectiveConfigHash`.
 */
export function renderVerificationTable(
  rows: readonly LedgerRow[],
  opts: { title?: string; tableName?: string; allowNonReportable?: boolean } = {},
): string {
  const checked = validateTableRows(rows, {
    tableName: opts.tableName ?? opts.title,
    allowNonReportable: opts.allowNonReportable,
  })
  const lines: string[] = []
  if (opts.title) {
    lines.push(`### ${opts.title}`)
    lines.push('')
  }
  if (checked.rows.length === 0) {
    lines.push('_No ledger rows recorded yet._')
    return lines.join('\n')
  }

  lines.push(
    `> \`benchmarkVersion=${checked.benchmarkVersion!.slice(0, 12)}\` · `
      + `\`effectiveConfigHash=${checked.effectiveConfigHash!.slice(0, 12)}\` · `
      + `rows=${checked.rows.length} · `
      + `certifying=${checked.certifyingAll ? 'yes' : 'non-certifying'}`,
  )
  lines.push('')
  lines.push(
    '| Suite | App | Split | Mode | LLM | Seed | SHA | Confirmed | Recall | Raw Prec | Strict Prec | Decoy/Unm FP | Valid Unplanted | Cost | Certifying |',
  )
  lines.push(
    '| :--- | :--- | :--- | :--- | :--- | ---: | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |',
  )

  const sorted = [...checked.rows].sort(
    (a, b) =>
      a.suite.localeCompare(b.suite)
      || a.split.localeCompare(b.split)
      || a.app.localeCompare(b.app)
      || a.seed - b.seed
      || a.repeat - b.repeat,
  )

  let totalConfirmed = 0
  let totalTargets = 0
  let totalDecoyFp = 0
  let totalUnmatchedFp = 0
  let totalValidUnplanted = 0
  let totalCostUsd = 0
  let hasMissingCost = false
  const recalls: number[] = []

  for (const r of sorted) {
    totalConfirmed += r.confirmed
    totalTargets += r.targets
    totalDecoyFp += r.decoyFalsePositives
    totalUnmatchedFp += r.unmatchedFalsePositives
    totalValidUnplanted += r.validUnplantedCount ?? 0
    if (r.costUsd === null || !Number.isFinite(r.costUsd)) {
      hasMissingCost = true
    } else {
      totalCostUsd += r.costUsd
    }
    if (r.recall !== null && Number.isFinite(r.recall)) recalls.push(r.recall)

    const shaLabel = r.dirty ? `${r.gitSha}*` : r.gitSha
    lines.push(
      `| ${r.suite} | ${r.app} | ${r.split} | ${r.mode} | ${r.llm} | ${r.seed} | \`${shaLabel}\` | `
        + `${r.confirmed}/${r.targets} | ${fmtPct(r.recall)} | ${fmtPct(r.rawPrecision)} | `
        + `${fmtPct(r.strictPrecision)} | ${r.decoyFalsePositives}/${r.unmatchedFalsePositives} | `
        + `${r.validUnplantedCount ?? 0} | ${fmtUsd(r.costUsd)} | ${r.certifying ? 'yes' : 'no'} |`,
    )
  }

  const aggRecall = totalTargets > 0 ? totalConfirmed / totalTargets : null
  const aggDenom = totalConfirmed + totalDecoyFp + totalUnmatchedFp
  const aggRawPrec = aggDenom > 0 ? totalConfirmed / aggDenom : null
  const spread =
    recalls.length >= 2
      ? ` (${fmtPct(Math.min(...recalls))}–${fmtPct(Math.max(...recalls))})`
      : ''
  lines.push(
    `| **TOTAL** | ${sorted.length} row(s) | — | — | — | — | — | `
      + `**${totalConfirmed}/${totalTargets}** | **${fmtPct(aggRecall)}**${spread} | `
      + `**${fmtPct(aggRawPrec)}** | — | **${totalDecoyFp}/${totalUnmatchedFp}** | `
      + `**${totalValidUnplanted}** | **${fmtUsd(hasMissingCost ? null : totalCostUsd)}** | ${checked.certifyingAll ? 'yes' : 'no'} |`,
  )
  return lines.join('\n')
}

/**
 * Group ledger rows by `(suite, split, mode, llm)` and render a complete Markdown document.
 * Fails closed if ANY table group mixes incompatible `benchmarkVersion` or `effectiveConfigHash`.
 */
export function renderVerificationDocument(
  rows: readonly LedgerRow[],
  opts: { suite?: BenchmarkSuiteName; allowNonReportable?: boolean } = {},
): string {
  const filtered = opts.suite ? rows.filter(r => r.suite === opts.suite) : [...rows]
  const lines: string[] = [
    '# Verification Tables (Generated from `benchmarks/results/ledger.jsonl`)',
    '',
    'Generated deterministically from committed ledger rows. Tables refuse mixed `benchmarkVersion` or `effectiveConfigHash` entries.',
    '',
  ]
  if (filtered.length === 0) {
    lines.push('_Ledger is empty (0 matching rows)._')
    return `${lines.join('\n')}\n`
  }

  const groups = new Map<string, LedgerRow[]>()
  for (const row of filtered) {
    const key = `${row.suite} · ${row.split} · ${row.mode} · ${row.llm}`
    const list = groups.get(key) ?? []
    list.push(row)
    groups.set(key, list)
  }

  for (const key of [...groups.keys()].sort()) {
    const groupRows = groups.get(key)!
    lines.push(
      renderVerificationTable(groupRows, {
        title: key,
        tableName: key,
        allowNonReportable: opts.allowNonReportable,
      }),
    )
    lines.push('')
  }
  return `${lines.join('\n')}\n`
}

export interface RenderTablesCliArgs {
  ledgerPath: string
  suite?: BenchmarkSuiteName
  outPath?: string
  checkOnly: boolean
  help: boolean
}

export function parseRenderTablesArgs(argv: readonly string[]): RenderTablesCliArgs {
  let ledgerPath = DEFAULT_LEDGER_PATH
  let suite: BenchmarkSuiteName | undefined
  let outPath: string | undefined
  let checkOnly = false
  let help = false

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--help' || arg === '-h') {
      help = true
      continue
    }
    if (arg === '--check') {
      checkOnly = true
      continue
    }
    if (arg === '--ledger') {
      const next = argv[++i]
      if (!next) throw new Error('--ledger requires a path')
      ledgerPath = next
      continue
    }
    if (arg === '--suite') {
      const next = argv[++i] as BenchmarkSuiteName | undefined
      if (!next) throw new Error('--suite requires a suite name')
      suite = next
      continue
    }
    if (arg === '--out') {
      const next = argv[++i]
      if (!next) throw new Error('--out requires a path')
      outPath = next
      continue
    }
    throw new Error(`Unknown flag: ${arg}`)
  }
  return { ledgerPath, suite, outPath, checkOnly, help }
}

const USAGE = `Render verification tables from benchmarks/results/ledger.jsonl

Usage:
  node scripts/render-verification-tables.ts [--ledger path] [--suite name] [--out path] [--check]

Fails (exit 1) if any table mixes incompatible benchmarkVersion or effectiveConfigHash values.
`

export function main(argv: readonly string[] = process.argv.slice(2)): number {
  let args: RenderTablesCliArgs
  try {
    args = parseRenderTablesArgs(argv)
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n\n${USAGE}`)
    return 2
  }
  if (args.help) {
    process.stdout.write(USAGE)
    return 0
  }
  try {
    const rows = readLedgerRows(args.ledgerPath)
    const md = renderVerificationDocument(rows, { suite: args.suite })
    if (!args.checkOnly) {
      if (args.outPath) {
        const abs = resolve(args.outPath)
        mkdirSync(dirname(abs), { recursive: true })
        writeFileSync(abs, md, 'utf8')
      } else {
        process.stdout.write(md)
      }
    }
    return 0
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`)
    return 1
  }
}

const isDirectEntry =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))

if (isDirectEntry) {
  process.exit(main(process.argv.slice(2)))
}
