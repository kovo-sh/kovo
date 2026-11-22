#!/usr/bin/env node
// realistic-bench x Guardian CLI: materialize one variant, run the real Guardian engines
// against it, grade with grader/score.ts, and print recall/precision by vuln class.
//
// Usage:
//   GUARDIAN_ALLOW_LOCAL_LAB=1 node benchmarks/realistic-bench/benchmark-realistic.ts \
//     --app acme-saas --seed 42 --split dev [--profile-mode v4-full] [--mode grey-box] \
//     [--verifier auto|docker|local-jq] [--out-json path] [--out-md path] [--out-findings path]
//
// Held-out: add --split heldout and export GUARDIAN_RB_HELDOUT_SALT (>=16 chars).
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { appNames } from './lib/types.ts'
import type { AppName, BenchMode, GradeInput } from './lib/types.ts'
import { assertLocalLabAllowed } from './lib/safety.ts'
import { gradeRun, renderScorecard, startRealisticApp } from './run.ts'
import { validateGradeInput } from './grader/schema.ts'
import { runGuardianAgainstMaterialized } from './guardian-adapter.ts'
import type { ProfileMode, VerifierChoice } from './guardian-adapter.ts'

interface CliArgs {
  app: AppName
  seed: number
  split: 'dev' | 'heldout'
  profileMode: ProfileMode
  mode: BenchMode
  verifier: VerifierChoice
  outJson?: string
  outMd?: string
  outFindings?: string
  heldOutSalt?: string
}

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!
    if (!a.startsWith('--')) throw new Error(`unexpected argument '${a}'`)
    const key = a.slice(2)
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) out[key] = true
    else { out[key] = next; i++ }
  }
  return out
}

function str(a: Record<string, string | boolean>, key: string): string | undefined {
  const v = a[key]
  return typeof v === 'string' ? v : undefined
}

function profileMode(raw: string | undefined): ProfileMode {
  if (!raw || raw === 'v4-full' || raw === 'full' || raw === 'v4') return 'v4-full'
  if (raw === 'v3-baseline' || raw === 'baseline' || raw === 'v3') return 'v3-baseline'
  throw new Error(`--profile-mode must be v4-full or v3-baseline (got '${raw}')`)
}

function benchMode(raw: string | undefined): BenchMode {
  if (!raw) return 'grey-box'
  if (raw === 'black-box' || raw === 'grey-box' || raw === 'white-box') return raw
  throw new Error(`--mode must be black-box, grey-box or white-box (got '${raw}')`)
}

function verifierChoice(raw: string | undefined): VerifierChoice {
  if (!raw || raw === 'auto') return 'auto'
  if (raw === 'docker' || raw === 'local-jq') return raw
  throw new Error(`--verifier must be auto, docker or local-jq (got '${raw}')`)
}

function readArgs(argv: string[]): CliArgs {
  const a = parseArgs(argv)
  const appRaw = str(a, 'app')
  if (!appRaw || !(appNames as readonly string[]).includes(appRaw)) {
    throw new Error(`--app must be one of ${appNames.join(', ')}`)
  }
  const seed = Number(str(a, 'seed') ?? '1')
  if (!Number.isInteger(seed) || seed <= 0) throw new Error('--seed must be a positive integer')
  const splitRaw = str(a, 'split') ?? 'dev'
  if (splitRaw !== 'dev' && splitRaw !== 'heldout') throw new Error(`--split must be dev or heldout (got '${splitRaw}')`)
  const split: 'dev' | 'heldout' = splitRaw
  const salt = split === 'heldout' ? (process.env.GUARDIAN_RB_HELDOUT_SALT ?? '') : ''
  if (split === 'dev' && seed >= 1_000_000) throw new Error(`dev seeds are 1..9999 (got ${seed}); use --split heldout`)
  if (split === 'heldout') {
    if (seed < 1_000_000) throw new Error(`held-out seeds are >= 1000000 (got ${seed}); use --split dev`)
    if (salt.length < 16) throw new Error('held-out runs require GUARDIAN_RB_HELDOUT_SALT (>=16 chars, never committed)')
  }
  return {
    app: appRaw as AppName,
    seed,
    split,
    profileMode: profileMode(str(a, 'profile-mode')),
    mode: benchMode(str(a, 'mode')),
    verifier: verifierChoice(str(a, 'verifier') ?? str(a, 'verifier-backend')),
    ...(str(a, 'out-json') ? { outJson: str(a, 'out-json') } : {}),
    ...(str(a, 'out-md') ? { outMd: str(a, 'out-md') } : {}),
    ...(str(a, 'out-findings') ? { outFindings: str(a, 'out-findings') } : {}),
    ...(salt ? { heldOutSalt: salt } : {}),
  }
}

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`
}

function writeOut(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, content)
}

async function main(): Promise<void> {
  const args = readArgs(process.argv.slice(2))
  assertLocalLabAllowed()

  const started = await startRealisticApp({
    app: args.app, seed: args.seed, ...(args.heldOutSalt ? { heldOutSalt: args.heldOutSalt } : {}),
  })
  try {
    process.stdout.write(`[realistic-bench] ${args.app} seed=${args.seed} (${started.plan.seedSet}) ${args.profileMode} ${args.mode} ${started.origin}\n`)
    const run = await runGuardianAgainstMaterialized({
      treeDir: started.sourceDir,
      seed: args.seed,
      app: args.app,
      profileMode: args.profileMode,
      verifierBackend: args.verifier,
      benchMode: args.mode,
      started,
    })

    const input: GradeInput = {
      groundTruth: started.groundTruth,
      findings: run.findings,
      oracleEvents: started.oracle.events(),
      requestLog: started.oracle.requests(),
      egressLog: started.oracle.egress(),
      telemetry: run.telemetry,
      mode: args.mode,
    }
    const valid = validateGradeInput(input)
    if (!valid.ok) throw new Error(`invalid grade input:\n  - ${valid.errors.join('\n  - ')}`)
    const card = gradeRun(input)

    const confirmedTp = card.vulns.filter(v => v.outcome === 'confirmed').length
    const lines: string[] = [
      '',
      `recall      ${card.confirmed}/${card.targets} (${pct(card.recall)})`,
      `precision   ${pct(card.precision)}  (tp=${confirmedTp} decoyFP=${card.decoyFalsePositives} unmatchedFP=${card.unmatchedFalsePositives})`,
      `decoys      ${card.decoyFalsePositives}/${card.decoys} false positives`,
      `funnel      surface ${card.funnel.surfaceDiscovered}/${card.funnel.targetVulns} -> hypotheses ${card.funnel.hypothesisFormed} -> signal ${card.funnel.signalObserved} -> spec ${card.funnel.specSubmitted} -> confirmed ${card.funnel.zeroLlmConfirmed}`,
      `engine      ${run.hypothesesFormed} hypotheses, ${run.signalsObserved} signals, ${run.proofGaps} proof gaps, verifier=${run.verifierBackend ?? 'n/a'}`,
      '',
      'by vuln class:',
    ]
    for (const cls of Object.keys(card.recallByClass).sort()) {
      const row = card.recallByClass[cls]!
      lines.push(`  ${cls.padEnd(20)} ${row.confirmed}/${row.targets} (${row.targets ? pct(row.confirmed / row.targets) : 'n/a'})`)
    }
    if (run.notes.length) {
      lines.push('', 'notes:')
      for (const n of run.notes) lines.push(`  - ${n}`)
    }
    process.stdout.write(`${lines.join('\n')}\n`)

    if (args.outFindings) writeOut(args.outFindings, `${JSON.stringify(run.findings, null, 2)}\n`)
    if (args.outJson) writeOut(args.outJson, `${renderScorecard(card, 'json')}\n`)
    if (args.outMd) writeOut(args.outMd, `${renderScorecard(card, 'md')}\n`)
    if (args.outJson) process.stdout.write(`\nwrote ${args.outJson}\n`)
    if (args.outMd) process.stdout.write(`wrote ${args.outMd}\n`)
    if (args.outFindings) process.stdout.write(`wrote ${args.outFindings}\n`)
  } finally {
    await started.stop()
  }
}

main().catch((err) => {
  process.stderr.write(`error: ${(err as Error).message}\n`)
  process.exit(1)
})
