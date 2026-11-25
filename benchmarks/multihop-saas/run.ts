// multihop-saas entrypoint: programmatic API + CLI.
//   startPaygrid({ seed, mode, twin?, asyncLatencyMs? }) -> StartedPaygrid
//   runReferenceSolvers(lab, chainIds?) -> Finding[]
//   gradeRun(input) / renderScorecard(card, format)
// CLI: list | seeds | serve | grade | selftest | anti-heuristic-check
//
// The suite is standalone: only node:* built-ins, native type stripping, loopback-only listeners.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  BenchMode, Finding, GradeInput, LabMode, OracleExport, Scorecard, SeedSet, SelftestResult, SelftestRow,
} from './lib/types.ts'
import { isAppName } from './lib/types.ts'
import { assertLocalLabAllowed } from './lib/safety.ts'
import { listSeeds } from './lib/domain-variant.ts'
import { ANTI_HEURISTIC_FLOOR_MAX, gradeRun, renderScorecard } from './lib/grader.ts'
import { startPaygrid, describeApp, PAYGRID_CHAINS, PAYGRID_TWINS } from './apps/paygrid/index.ts'
import type { StartedPaygrid } from './apps/paygrid/index.ts'
import { runReferenceSolvers } from './apps/paygrid/solvers/index.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
export const BENCH_ROOT = HERE

export { startPaygrid, runReferenceSolvers, gradeRun, renderScorecard, ANTI_HEURISTIC_FLOOR_MAX, listSeeds }
export type { StartedPaygrid, Scorecard, Finding, GradeInput, OracleExport }

export interface LabCatalogue {
  apps: Array<{
    name: string
    services: number
    chains: Array<{ id: string; hops: number; vulnClass: string; terminalKind: string }>
    twins: Array<{ id: string; baseChainId: string; decoyHopIds: string[]; enforcedAtHopId: string }>
  }>
}

export function catalog(): LabCatalogue {
  const info = describeApp()
  return {
    apps: [{
      name: info.app,
      services: info.services,
      chains: PAYGRID_CHAINS.map((chain) => ({
        id: chain.id,
        hops: chain.hops.length,
        vulnClass: chain.vulnClass,
        terminalKind: chain.terminal.kind,
      })),
      twins: PAYGRID_TWINS.map((twin) => ({
        id: twin.id,
        baseChainId: twin.baseChainId,
        decoyHopIds: twin.decoyHopIds,
        enforcedAtHopId: twin.enforcedAtHopId,
      })),
    }],
  }
}

export async function runLab(
  options: { app?: string; seed: number; mode: LabMode; twin?: string; asyncLatencyMs?: number },
): Promise<StartedPaygrid> {
  const app = options.app ?? 'paygrid'
  if (!isAppName(app)) throw new Error(`unknown app '${app}': known apps are paygrid`)
  if (app !== 'paygrid') throw new Error(`app '${app}' is not available yet`)
  return startPaygrid({
    seed: options.seed,
    mode: options.mode,
    twin: options.twin,
    asyncLatencyMs: options.asyncLatencyMs,
  })
}

export function gradeLab(lab: StartedPaygrid, findings: Finding[]): Scorecard {
  return gradeRun({ groundTruth: lab.groundTruth, findings, oracle: lab.export() })
}

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!
    if (!arg.startsWith('--')) continue
    const key = arg.slice(2)
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) out[key] = true
    else {
      out[key] = next
      i++
    }
  }
  return out
}

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(isAbsolute(path) ? path : resolve(process.cwd(), path), 'utf8')) as T
}

function asMode(value: unknown): LabMode {
  if (value === undefined) return 'vulnerable'
  if (value === 'vulnerable' || value === 'hardened') return value
  throw new Error(`--mode must be vulnerable or hardened, got '${String(value)}'`)
}

function asBriefingMode(value: unknown): BenchMode {
  if (value === undefined) return 'grey-box'
  if (value === 'black-box' || value === 'grey-box' || value === 'white-box') return value
  throw new Error(`--briefing must be black-box, grey-box or white-box`)
}

function outDirFor(a: Record<string, string | boolean>): string {
  return a['out-dir'] ? resolve(process.cwd(), String(a['out-dir'])) : join(HERE, 'out')
}

function writeArtifacts(
  lab: StartedPaygrid, findings: Finding[], card: Scorecard, briefingMode: BenchMode,
  outDir = outDirFor({}),
): string {
  mkdirSync(outDir, { recursive: true })
  const base = join(outDir, `${lab.app}-${lab.seed}-${lab.labMode}${lab.twinId ? `-${lab.twinId}` : ''}`)
  writeFileSync(`${base}.groundtruth.json`, `${JSON.stringify(lab.groundTruth, null, 2)}\n`)
  writeFileSync(`${base}.oracle.json`, `${JSON.stringify(lab.export(), null, 2)}\n`)
  writeFileSync(`${base}.findings.json`, `${JSON.stringify(findings, null, 2)}\n`)
  writeFileSync(`${base}.briefing.json`, `${JSON.stringify(lab.briefing(briefingMode), null, 2)}\n`)
  writeFileSync(`${base}.scorecard.json`, renderScorecard(card, 'json'))
  writeFileSync(`${base}.scorecard.md`, renderScorecard(card, 'md'))
  return base
}

function cmdList(a: Record<string, string | boolean>): void {
  const data = catalog()
  if (a.json) {
    process.stdout.write(`${JSON.stringify(data, null, 2)}\n`)
    return
  }
  for (const app of data.apps) {
    process.stdout.write(`${app.name}: ${app.services} services, ${app.chains.length} chains, ${app.twins.length} twins\n`)
    for (const chain of app.chains) {
      process.stdout.write(`  ${chain.id} (${chain.hops} hops) ${chain.vulnClass} -> ${chain.terminalKind}\n`)
    }
    for (const twin of app.twins) {
      process.stdout.write(`  ${twin.id} (base ${twin.baseChainId}, decoy hops ${twin.decoyHopIds.join(',')}, enforced ${twin.enforcedAtHopId})\n`)
    }
  }
}

function cmdSeeds(a: Record<string, string | boolean>): void {
  const set = (a.set ? String(a.set) : 'dev') as SeedSet
  if (set !== 'dev' && set !== 'held-out') throw new Error('--set must be dev or held-out')
  if (a.salt !== undefined) {
    throw new Error('never pass the held-out salt on the command line; set GUARDIAN_RB_HELDOUT_SALT instead')
  }
  const n = Number(a.n ?? 5)
  process.stdout.write(`${JSON.stringify(listSeeds(set, n))}\n`)
}

async function cmdServe(a: Record<string, string | boolean>): Promise<void> {
  assertLocalLabAllowed()
  if (a['held-out-salt'] !== undefined) {
    throw new Error('never pass the held-out salt on the command line; set GUARDIAN_RB_HELDOUT_SALT instead')
  }
  const mode = asMode(a.mode)
  const briefingMode = asBriefingMode(a.briefing)
  const lab = await runLab({
    app: a.app ? String(a.app) : 'paygrid',
    seed: Number(a.seed ?? 1),
    mode,
    twin: a.twin ? String(a.twin) : undefined,
    asyncLatencyMs: a['async-latency-ms'] !== undefined ? Number(a['async-latency-ms']) : undefined,
  })
  process.stdout.write(`${JSON.stringify(lab.briefing(briefingMode), null, 2)}\n`)

  if (a.once) {
    const findings = await runReferenceSolvers(lab)
    const card = gradeLab(lab, findings)
    const base = writeArtifacts(lab, findings, card, briefingMode, outDirFor(a))
    process.stderr.write(`[multihop-saas] artifacts -> ${base}.{groundtruth,oracle,findings,scorecard}.*\n`)
    process.stdout.write(renderScorecard(card, 'json'))
    await lab.stop()
    if (!card.gate.pass) process.exit(2)
    return
  }

  process.stderr.write(
    `[multihop-saas] ${lab.app} seed=${lab.seed} (${lab.seedSet}) ${lab.labMode}` +
      `${lab.twinId ? ` twin=${lab.twinId}` : ''} entry=${lab.entryOrigin} — Ctrl-C to stop\n`,
  )
  const shutdown = async (): Promise<void> => {
    const findings = await runReferenceSolvers(lab).catch(() => [])
    const card = gradeLab(lab, findings)
    const base = writeArtifacts(lab, findings, card, briefingMode, outDirFor(a))
    process.stderr.write(`[multihop-saas] artifacts -> ${base}.*\n`)
    await lab.stop()
    process.exit(0)
  }
  process.on('SIGINT', () => void shutdown())
  process.on('SIGTERM', () => void shutdown())
}

function gradeInputFromArgs(a: Record<string, string | boolean>): GradeInput {
  return {
    groundTruth: readJson(String(a.truth)),
    findings: readJson(String(a.findings)),
    oracle: readJson(String(a.oracle)),
  }
}

function cmdGrade(a: Record<string, string | boolean>): void {
  if (!a.truth || !a.findings || !a.oracle) {
    throw new Error('grade requires --truth <file> --findings <file> --oracle <file>')
  }
  const card = gradeRun(gradeInputFromArgs(a))
  if (a.json) writeFileSync(resolve(process.cwd(), String(a.json)), renderScorecard(card, 'json'))
  if (a.md) writeFileSync(resolve(process.cwd(), String(a.md)), renderScorecard(card, 'md'))
  process.stdout.write(renderScorecard(card, a.md || a.json ? 'json' : 'md'))
}

async function cmdSelftest(a: Record<string, string | boolean>): Promise<void> {
  assertLocalLabAllowed()
  if (a['held-out-salt'] !== undefined) {
    throw new Error('never pass the held-out salt on the command line; set GUARDIAN_RB_HELDOUT_SALT instead')
  }
  const seeds = String(a.seeds ?? '1,2,3').split(',').map((value) => Number(value.trim()))
    .filter((value) => Number.isFinite(value))
  if (seeds.length === 0) throw new Error('--seeds must list at least one seed')
  const latency = a['async-latency-ms'] !== undefined ? Number(a['async-latency-ms']) : 10
  const rows: SelftestRow[] = []

  for (const seed of seeds) {
    const lab = await runLab({ seed, mode: 'vulnerable', asyncLatencyMs: latency })
    try {
      const findings = await runReferenceSolvers(lab)
      const card = gradeLab(lab, findings)
      const ok = findings.length === 4 && card.gate.pass && card.tp === 4 && card.precision === 1 && card.recall === 1
      rows.push({ scope: 'vulnerable', seed, ok, detail: `findings=${findings.length} tp=${card.tp} precision=${card.precision}` })
    } finally {
      await lab.stop()
    }

    const hardened = await runLab({ seed, mode: 'hardened', asyncLatencyMs: latency })
    try {
      const findings = await runReferenceSolvers(hardened)
      const events = hardened.export().events
      const total = events.hops.length + events.edges.length + events.controls.length + events.terminals.length
      rows.push({
        scope: 'hardened', seed, ok: findings.length === 0 && total === 0,
        detail: `findings=${findings.length} events=${total}`,
      })
    } finally {
      await hardened.stop()
    }

    for (const twin of [
      { id: 'PG-D1', chain: 'PG-C1' },
      { id: 'PG-D2', chain: 'PG-C2' },
      { id: 'PG-D3', chain: 'PG-C3' },
    ]) {
      const labTwin = await runLab({ seed, mode: 'vulnerable', twin: twin.id, asyncLatencyMs: latency })
      try {
        const findings = await runReferenceSolvers(labTwin, [twin.chain])
        const evaluation = labTwin.oracle.evaluate(twin.chain)
        const terminals = labTwin.export().events.terminals.length
        rows.push({
          scope: twin.id, seed,
          ok: findings.length === 0 && terminals === 0 && evaluation.hopsObserved >= 2 && !evaluation.confirmed,
          detail: `hops=${evaluation.hopsObserved} terminals=${terminals} findings=${findings.length} drop=${evaluation.dropReason ?? 'none'}`,
        })
      } finally {
        await labTwin.stop()
      }
    }
  }

  const failures = rows.filter((row) => !row.ok)
  const result: SelftestResult = {
    summary: `${rows.length - failures.length}/${rows.length} selftest checks pass`,
    rows,
  }
  for (const row of rows) {
    process.stdout.write(`${row.ok ? 'PASS' : 'FAIL'} ${row.scope} seed=${row.seed} ${row.detail}\n`)
  }
  process.stdout.write(`${result.summary}\n`)
  if (failures.length > 0) process.exit(2)
}

function cmdAntiHeuristicCheck(a: Record<string, string | boolean>): void {
  const maxRecall = a['max-recall'] !== undefined ? Number(a['max-recall']) : ANTI_HEURISTIC_FLOOR_MAX
  let card: Scorecard
  if (a.scorecard) {
    card = readJson<Scorecard>(String(a.scorecard))
  } else {
    card = gradeRun(gradeInputFromArgs(a))
  }
  const pass = card.recall <= maxRecall
  process.stdout.write(`${JSON.stringify({
    app: card.app, seed: card.seed, seedSet: card.seedSet, mode: card.mode, twin: card.twin,
    heuristicFloor: card.recall, maxRecall, pass,
  }, null, 2)}\n`)
  if (!pass) process.exit(2)
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2)
  const a = parseArgs(rest)
  switch (command) {
    case 'list':
      return cmdList(a)
    case 'seeds':
      return cmdSeeds(a)
    case 'serve':
      return cmdServe(a)
    case 'grade':
      return cmdGrade(a)
    case 'selftest':
      return cmdSelftest(a)
    case 'anti-heuristic-check':
      return cmdAntiHeuristicCheck(a)
    default:
      process.stderr.write(
        'usage: run.ts <list|seeds|serve|grade|selftest|anti-heuristic-check> [--flags]\n',
      )
      process.exit(1)
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    process.stderr.write(`error: ${(err as Error).message}\n`)
    process.exit(1)
  })
}
