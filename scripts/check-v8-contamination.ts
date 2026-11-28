#!/usr/bin/env node
/**
 * v8 Anti-Contamination CI Lint (plans/v8.md §Anti-Goodhart).
 *
 * Scans `src/server/**` and `src/skills/**` (excluding test/benchmark files) and fails fast
 * (exit 1) if any v8 benchmark literal leaks into production engine or skill source code:
 *
 *   - Archetype names:           paygrid, shipforge, nexusiam, connecthub
 *   - Chain / hardened-twin IDs: PG-C*, PG-D*, SF-C*, SF-D*, NX-C*, NX-D*, CH-C*, CH-D*
 *   - Internal lab hostnames:    vault.internal, registry.internal, billing.internal
 *   - Synthetic canary prefixes: mh_fake_
 *
 * Pure scan API (`scanSourceTreeForContamination`) is exported so unit tests can assert both
 * clean-repo PASS and synthetic-leak FAIL with exact file/line/token reporting.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, posix, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

export type ContaminationCategory =
  | 'archetype_name'
  | 'chain_or_twin_id'
  | 'internal_hostname'
  | 'synthetic_canary'
  | 'structural_lab_artifact'

export interface ContaminationRule {
  id: string
  category: ContaminationCategory
  pattern: RegExp
  description: string
}

export interface ContaminationHit {
  /** Repo-relative POSIX path. */
  file: string
  /** 1-based line number. */
  line: number
  /** 1-based column number. */
  column: number
  /** Exact matched forbidden token. */
  token: string
  category: ContaminationCategory
  ruleId: string
}

export interface ContaminationScanOptions {
  /** Relative directories under rootDir to scan (default: ['src/server', 'src/skills']). */
  dirs?: readonly string[]
  /** Override rules (default: V8_CONTAMINATION_RULES). */
  rules?: readonly ContaminationRule[]
}

export interface ContaminationScanResult {
  ok: boolean
  rootDir: string
  scannedDirs: string[]
  filesScanned: number
  hits: ContaminationHit[]
  durationMs: number
}

export const DEFAULT_SCAN_DIRS = ['src/server', 'src/skills'] as const

const EXCLUDED_DIR_NAMES = new Set([
  'node_modules',
  '.git',
  'tests',
  '__tests__',
  'benchmarks',
])

const EXCLUDED_FILE_RE = /(?:\.test|\.spec)\.[^./\\]+$/i

export const V8_CONTAMINATION_RULES: readonly ContaminationRule[] = [
  {
    id: 'v8-archetype-name',
    category: 'archetype_name',
    pattern: /(?:paygrid|shipforge|nexusiam|connecthub)/gi,
    description: 'v8 multihop-saas archetype name',
  },
  {
    id: 'v8-chain-or-twin-id',
    category: 'chain_or_twin_id',
    pattern: /(?<![A-Za-z0-9])(?:PG|SF|NX|CH)-[CD]\d+(?![A-Za-z0-9])/gi,
    description: 'v8 multihop-saas chain or hardened-twin ID',
  },
  {
    id: 'v8-internal-hostname',
    category: 'internal_hostname',
    pattern: /(?<![A-Za-z0-9-])(?:vault|registry|billing)\.internal(?![A-Za-z0-9-])/gi,
    description: 'v8 multihop-saas internal service hostname',
  },
  {
    id: 'v8-synthetic-canary',
    category: 'synthetic_canary',
    pattern: /mh_fake_/gi,
    description: 'v8 multihop-saas synthetic canary prefix',
  },
  {
    id: 'lab-fast-lab-profile',
    category: 'structural_lab_artifact',
    pattern: /\bfast_lab\b/gi,
    description: 'lab-tuned async polling profile literal',
  },
  {
    id: 'lab-dual-org-cache-bleed',
    category: 'structural_lab_artifact',
    pattern: /\bdual_org_cache_bleed\b/gi,
    description: 'bespoke multihop-saas sub-oracle mode name',
  },
  {
    id: 'lab-nfkc-collision',
    category: 'structural_lab_artifact',
    pattern: /nfkc-collision/gi,
    description: 'benchmark-specific NFKC collision fixture label',
  },
  {
    id: 'lab-split-refund-ledger-break',
    category: 'structural_lab_artifact',
    pattern: /\bsplit_refund_ledger_break\b/gi,
    description: 'multihop-saas chain name literal',
  },
  {
    id: 'lab-billingz-token',
    category: 'structural_lab_artifact',
    pattern: /\bbillingz\b/gi,
    description: 'target-specific service slug literal',
  },
  {
    id: 'lab-whsec-prefix',
    category: 'structural_lab_artifact',
    pattern: /whsec_/gi,
    description: 'hardcoded webhook secret prefix literal',
  },
  {
    id: 'lab-xfer-prefix',
    category: 'structural_lab_artifact',
    pattern: /xfer_/gi,
    description: 'hardcoded transfer ID prefix literal',
  },
  {
    id: 'lab-hardened-twin',
    category: 'structural_lab_artifact',
    pattern: /hardened_twin/gi,
    description: 'benchmark hardened-twin coaching literal',
  },
  {
    id: 'lab-rbs-prefix',
    category: 'structural_lab_artifact',
    pattern: /\brbs_/gi,
    description: 'realistic-bench secret token prefix literal',
  },
] as const

/**
 * Narrow per-file, per-rule allowlist for structural lab-artifact tokens pending Phase 0/1-2 cleanup.
 * Every entry MUST be tightened to zero as its owning phase lands (except Stripe secret redaction in redact.ts).
 */
export const TEMPORARY_STRUCTURAL_ALLOWLIST: Readonly<Record<string, ReadonlySet<string>>> = {
  // Legitimate outbound Stripe webhook secret redactor (not overfitting):
  'src/server/redact.ts': new Set(['lab-whsec-prefix']),
  // TODO(Phase 0): retired by sibling Phase 0 non-kernel cleanup streams:
  'src/server/assignment-brief.ts': new Set(['lab-fast-lab-profile', 'lab-hardened-twin']),
  'src/server/exploiter-tools.ts': new Set(['lab-dual-org-cache-bleed']),
  'src/server/probes/xxe.ts': new Set(['lab-rbs-prefix']),
  // TODO(Phase 1-2): confirmation-kernel & compiler files retired in Phases 1–2 (Opus R3-05 reviewed):
  'src/server/evidence-provenance.ts': new Set(['lab-rbs-prefix']),
  'src/server/oracle-spec.ts': new Set(['lab-split-refund-ledger-break']),
  'src/server/v8-oracle-families.ts': new Set(['lab-dual-org-cache-bleed']),
  'src/server/v8-oracle-hydrate.ts': new Set(['lab-dual-org-cache-bleed']),
  'src/server/causal-proof-compiler.ts': new Set(['lab-dual-org-cache-bleed']),
  'src/server/trace-proof-compiler.ts': new Set(['lab-split-refund-ledger-break']),
  'src/server/derived-custody.ts': new Set(['lab-fast-lab-profile']),
  'src/server/verify-rpc.ts': new Set(['lab-fast-lab-profile']),
}

function toPosixRelative(rootDir: string, absPath: string): string {
  const rel = relative(rootDir, absPath)
  return sep === '/' ? rel : rel.split(sep).join(posix.sep)
}

function collectFiles(rootDir: string, dirPath: string, out: string[]): void {
  if (!existsSync(dirPath)) return
  const entries = readdirSync(dirPath, { withFileTypes: true })
  entries.sort((a, b) => a.name.localeCompare(b.name))
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue
    const fullPath = join(dirPath, entry.name)
    if (entry.isDirectory()) {
      if (EXCLUDED_DIR_NAMES.has(entry.name)) continue
      collectFiles(rootDir, fullPath, out)
    } else if (entry.isFile()) {
      if (EXCLUDED_FILE_RE.test(entry.name)) continue
      out.push(fullPath)
    }
  }
}

/** Scan a single file's text line-by-line for forbidden v8 benchmark tokens. */
export function scanTextForContamination(
  file: string,
  content: string,
  rules: readonly ContaminationRule[] = V8_CONTAMINATION_RULES,
): ContaminationHit[] {
  const hits: ContaminationHit[] = []
  const allowedRuleIds = TEMPORARY_STRUCTURAL_ALLOWLIST[file]
  const lines = content.split(/\r?\n/)
  for (let lineIdx = 0; lineIdx < lines.length; lineIdx += 1) {
    const lineText = lines[lineIdx]!
    for (const rule of rules) {
      if (allowedRuleIds?.has(rule.id)) continue
      const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`
      const re = new RegExp(rule.pattern.source, flags)
      let match: RegExpExecArray | null
      while ((match = re.exec(lineText)) !== null) {
        hits.push({
          file,
          line: lineIdx + 1,
          column: match.index + 1,
          token: match[0],
          category: rule.category,
          ruleId: rule.id,
        })
        if (match[0].length === 0) re.lastIndex += 1
      }
    }
  }
  return hits
}

/**
 * Pure directory scanner for v8 benchmark contamination across `src/server/**` and `src/skills/**`.
 * Excludes test files (`*.test.*`, `*.spec.*`), test/benchmark directories, and binary files.
 */
export function scanSourceTreeForContamination(
  rootDir: string,
  opts: ContaminationScanOptions = {},
): ContaminationScanResult {
  const startedAt = performance.now()
  const resolvedRoot = resolve(rootDir)
  const dirs = opts.dirs ?? DEFAULT_SCAN_DIRS
  const rules = opts.rules ?? V8_CONTAMINATION_RULES
  const scannedDirs: string[] = []
  const files: string[] = []

  for (const relDir of dirs) {
    const absDir = resolve(resolvedRoot, relDir)
    if (!existsSync(absDir)) continue
    scannedDirs.push(toPosixRelative(resolvedRoot, absDir))
    collectFiles(resolvedRoot, absDir, files)
  }

  const hits: ContaminationHit[] = []
  let filesScanned = 0
  for (const absFile of files) {
    const raw = readFileSync(absFile)
    // Skip binary files cleanly.
    if (raw.includes(0)) continue
    filesScanned += 1
    const relFile = toPosixRelative(resolvedRoot, absFile)
    const fileHits = scanTextForContamination(relFile, raw.toString('utf8'), rules)
    for (const hit of fileHits) hits.push(hit)
  }

  const durationMs = Math.max(0, Math.round(performance.now() - startedAt))
  return {
    ok: hits.length === 0,
    rootDir: resolvedRoot,
    scannedDirs,
    filesScanned,
    hits,
    durationMs,
  }
}

export function formatContaminationReport(result: ContaminationScanResult): string {
  if (result.ok) {
    return (
      `v8-contamination: PASS (${result.filesScanned} files scanned across `
      + `${result.scannedDirs.join(', ') || '(none)'} in ${result.durationMs}ms, 0 hits)`
    )
  }
  const lines = [
    `v8-contamination: FAIL (${result.hits.length} forbidden v8 benchmark token(s) found in `
    + `${result.filesScanned} files in ${result.durationMs}ms):`,
  ]
  for (const hit of result.hits) {
    lines.push(`  ${hit.file}:${hit.line}:${hit.column} [${hit.category}] ${hit.token}`)
  }
  return lines.join('\n')
}

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

const usage = `Kovo v8 Anti-Contamination CI Lint (plans/v8.md §Anti-Goodhart)

Usage:
  node scripts/check-v8-contamination.ts [--root <dir>] [--json] [--help]

Scans src/server/** and src/skills/** (excluding tests/benchmarks) and exits 1 if any
v8 benchmark archetype name, chain/twin ID, internal hostname, or synthetic canary prefix appears.
`

export function main(argv: string[] = process.argv.slice(2)): number {
  let rootDir = REPO_ROOT
  let json = false
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--help' || arg === '-h') {
      process.stdout.write(usage)
      return 0
    }
    if (arg === '--json') {
      json = true
      continue
    }
    if (arg === '--root') {
      const next = argv[i + 1]
      if (!next) {
        process.stderr.write('error: --root requires a directory argument\n')
        return 2
      }
      rootDir = resolve(next)
      i += 1
      continue
    }
    process.stderr.write(`error: unknown argument '${arg}'\n`)
    return 2
  }

  const result = scanSourceTreeForContamination(rootDir)
  if (json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
  } else {
    const report = `${formatContaminationReport(result)}\n`
    if (result.ok) process.stdout.write(report)
    else process.stderr.write(report)
  }
  return result.ok ? 0 : 1
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(resolve(process.argv[1])).href : false
if (isMain) {
  process.exit(main())
}
