#!/usr/bin/env node
/**
 * R3-01 (`plans/claude_quality_3.md` §1) — Monotone `tsc --noEmit --extendedDiagnostics`
 * memory & wall-time budget ratchet.
 *
 * Parses `Memory used: <N>K` and `Total time: <N>s` from `tsc --noEmit --extendedDiagnostics`
 * (either by running `tsc` directly with `--max-old-space-size=6144` or from `--from-file <path>`)
 * and enforces generous monotone ceilings so CI heap OOM never sneaks back silently.
 *
 * Usage:
 *   node scripts/check-tsc-budget.ts [--from-file <path>] [--max-memory-kb <N>] [--max-time-sec <N>] [--heap-mb <N>] [--json]
 */
import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export interface TscDiagnostics {
  files: number | null
  linesOfTypeScript: number | null
  instantiations: number | null
  memoryUsedKb: number | null
  programTimeSec: number | null
  bindTimeSec: number | null
  checkTimeSec: number | null
  totalTimeSec: number | null
}

export interface TscBudgetLimits {
  baselineMemoryUsedKb: number
  maxMemoryUsedKb: number
  baselineTotalTimeSec: number
  maxTotalTimeSec: number
}

export interface TscBudgetResult {
  ok: boolean
  diagnostics: TscDiagnostics
  limits: TscBudgetLimits
  violations: string[]
}

/**
 * Monotone baseline & ceilings recorded at R3-01 landing (~2.49 GB RSS / ~24s local check).
 * Ceilings leave headroom for GitHub Actions runner jitter while failing well below the 6144 MB heap cap.
 */
export const TSC_BUDGET_BASELINE: Readonly<TscBudgetLimits> = Object.freeze({
  baselineMemoryUsedKb: 2_500_000,
  maxMemoryUsedKb: 4_200_000,
  baselineTotalTimeSec: 25,
  maxTotalTimeSec: 120,
})

function matchInt(text: string, re: RegExp): number | null {
  const m = re.exec(text)
  if (!m?.[1]) return null
  const n = Number.parseInt(m[1], 10)
  return Number.isFinite(n) ? n : null
}

function matchFloat(text: string, re: RegExp): number | null {
  const m = re.exec(text)
  if (!m?.[1]) return null
  const n = Number.parseFloat(m[1])
  return Number.isFinite(n) ? n : null
}

/** Parse key metrics from `tsc --noEmit --extendedDiagnostics` output. */
export function parseTscDiagnostics(output: string): TscDiagnostics {
  return {
    files: matchInt(output, /^\s*Files:\s*(\d+)\s*$/m),
    linesOfTypeScript: matchInt(output, /^\s*Lines of TypeScript:\s*(\d+)\s*$/m),
    instantiations: matchInt(output, /^\s*Instantiations:\s*(\d+)\s*$/m),
    memoryUsedKb: matchInt(output, /^\s*Memory used:\s*(\d+)K\s*$/m),
    programTimeSec: matchFloat(output, /^\s*Program time:\s*([0-9.]+)s\s*$/m),
    bindTimeSec: matchFloat(output, /^\s*Bind time:\s*([0-9.]+)s\s*$/m),
    checkTimeSec: matchFloat(output, /^\s*Check time:\s*([0-9.]+)s\s*$/m),
    totalTimeSec: matchFloat(output, /^\s*Total time:\s*([0-9.]+)s\s*$/m),
  }
}

/** Evaluate parsed `tsc --extendedDiagnostics` output against monotone memory and wall-time ceilings. */
export function evaluateTscBudget(
  diagnostics: TscDiagnostics,
  overrides: Partial<TscBudgetLimits> = {},
): TscBudgetResult {
  const limits: TscBudgetLimits = {
    baselineMemoryUsedKb: overrides.baselineMemoryUsedKb ?? TSC_BUDGET_BASELINE.baselineMemoryUsedKb,
    maxMemoryUsedKb: overrides.maxMemoryUsedKb ?? TSC_BUDGET_BASELINE.maxMemoryUsedKb,
    baselineTotalTimeSec: overrides.baselineTotalTimeSec ?? TSC_BUDGET_BASELINE.baselineTotalTimeSec,
    maxTotalTimeSec: overrides.maxTotalTimeSec ?? TSC_BUDGET_BASELINE.maxTotalTimeSec,
  }
  const violations: string[] = []
  if (diagnostics.memoryUsedKb === null) {
    violations.push('missing "Memory used: <N>K" line in tsc --extendedDiagnostics output')
  } else if (diagnostics.memoryUsedKb > limits.maxMemoryUsedKb) {
    violations.push(
      `tsc memoryUsedKb=${diagnostics.memoryUsedKb}K (${(diagnostics.memoryUsedKb / 1024).toFixed(0)} MiB) exceeds ceiling ${limits.maxMemoryUsedKb}K (${(limits.maxMemoryUsedKb / 1024).toFixed(0)} MiB; baseline ${limits.baselineMemoryUsedKb}K)`,
    )
  }
  if (diagnostics.totalTimeSec === null) {
    violations.push('missing "Total time: <N>s" line in tsc --extendedDiagnostics output')
  } else if (diagnostics.totalTimeSec > limits.maxTotalTimeSec) {
    violations.push(
      `tsc totalTimeSec=${diagnostics.totalTimeSec.toFixed(2)}s exceeds ceiling ${limits.maxTotalTimeSec}s (baseline ${limits.baselineTotalTimeSec}s)`,
    )
  }
  return { ok: violations.length === 0, diagnostics, limits, violations }
}

function buildNodeOptionsWithHeap(existing: string | undefined, heapMb: number): string {
  const trimmed = (existing ?? '').trim()
  if (/--max-old-space-size=\d+/.test(trimmed)) return trimmed
  return trimmed ? `${trimmed} --max-old-space-size=${heapMb}` : `--max-old-space-size=${heapMb}`
}

function runCli(): void {
  const args = process.argv.slice(2)
  let fromFile: string | null = null
  let maxMemoryKb = TSC_BUDGET_BASELINE.maxMemoryUsedKb
  let maxTimeSec = TSC_BUDGET_BASELINE.maxTotalTimeSec
  let heapMb = 6144
  let jsonOut = false
  let rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]
    if (arg === '--from-file') {
      fromFile = args[++i] ?? ''
    } else if (arg === '--max-memory-kb') {
      maxMemoryKb = Number.parseInt(args[++i] ?? '', 10)
    } else if (arg === '--max-time-sec') {
      maxTimeSec = Number.parseFloat(args[++i] ?? '')
    } else if (arg === '--heap-mb') {
      heapMb = Number.parseInt(args[++i] ?? '', 10)
    } else if (arg === '--root') {
      rootDir = resolve(args[++i] ?? rootDir)
    } else if (arg === '--json') {
      jsonOut = true
    } else if (arg === '-h' || arg === '--help') {
      console.log('Usage: node scripts/check-tsc-budget.ts [--from-file <path>] [--max-memory-kb <N>] [--max-time-sec <N>] [--heap-mb <N>] [--root <dir>] [--json]')
      process.exit(0)
    } else {
      console.error(`check-tsc-budget: unknown option: ${arg}`)
      process.exit(2)
    }
  }

  let output = ''
  if (fromFile !== null) {
    if (!fromFile || !existsSync(fromFile)) {
      console.error(`check-tsc-budget: FAIL — diagnostics file not found: ${fromFile}`)
      process.exit(2)
    }
    output = readFileSync(fromFile, 'utf8')
  } else {
    const localTsc = join(rootDir, 'node_modules/.bin/tsc')
    const cmd = existsSync(localTsc) ? localTsc : 'npx'
    const cmdArgs = existsSync(localTsc)
      ? ['--noEmit', '--extendedDiagnostics']
      : ['tsc', '--noEmit', '--extendedDiagnostics']
    const res = spawnSync(cmd, cmdArgs, {
      cwd: rootDir,
      encoding: 'utf8',
      env: {
        ...process.env,
        NODE_OPTIONS: buildNodeOptionsWithHeap(process.env.NODE_OPTIONS, heapMb),
      },
      maxBuffer: 16 * 1024 * 1024,
    })
    output = `${res.stdout ?? ''}\n${res.stderr ?? ''}`
    if (res.status !== 0) {
      if (!jsonOut) {
        process.stderr.write(output)
        console.error(`check-tsc-budget: FAIL — tsc exited ${res.status ?? 'signal'}`)
      } else {
        console.log(JSON.stringify({ ok: false, tscExitCode: res.status, diagnostics: parseTscDiagnostics(output), violations: [`tsc exited ${res.status ?? 'signal'}`] }))
      }
      process.exit(res.status ?? 1)
    }
  }

  const diagnostics = parseTscDiagnostics(output)
  const result = evaluateTscBudget(diagnostics, { maxMemoryUsedKb: maxMemoryKb, maxTotalTimeSec: maxTimeSec })

  if (jsonOut) {
    console.log(JSON.stringify(result))
  } else if (result.ok) {
    const memMb = ((diagnostics.memoryUsedKb ?? 0) / 1024).toFixed(0)
    const maxMb = (result.limits.maxMemoryUsedKb / 1024).toFixed(0)
    console.log(
      `check-tsc-budget: PASS (memory=${diagnostics.memoryUsedKb}K/${memMb}MiB <= ${result.limits.maxMemoryUsedKb}K/${maxMb}MiB, totalTime=${diagnostics.totalTimeSec?.toFixed(2)}s <= ${result.limits.maxTotalTimeSec}s, files=${diagnostics.files ?? '?'}, tsLines=${diagnostics.linesOfTypeScript ?? '?'})`,
    )
  } else {
    console.error(`check-tsc-budget: FAIL — ${result.violations.join('; ')}`)
  }
  process.exit(result.ok ? 0 : 1)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runCli()
}
