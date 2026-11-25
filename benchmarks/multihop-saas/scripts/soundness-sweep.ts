// Multi-archetype soundness & white-box leakage sweep across all 4 multihop-saas archetypes
// (paygrid, shipforge, nexusiam, connecthub).
//
// Sweeps dev seeds 1..N (default N=30) and optional salted held-out seeds 1000001..1000000+M
// (--held-out [M], requiring GUARDIAN_RB_HELDOUT_SALT). Verifies:
//   1. 100% vulnerable solver pass rate (4/4 chains per archetype per seed -> ChainOracle v2 + Mode-A receipt)
//   2. 100% hardened silence (0 findings, 0 oracle events)
//   3. 100% partial-hop twin silence (0 findings, 0 terminal events, >=2 early hops exercised)
//   4. 0 white-box materialization leakage hits across all 4 archetype marker families
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, extname, isAbsolute, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import type { ChainOracle } from '../lib/chain-oracle.ts'
import { HELDOUT_MIN, requireHeldOutSalt, seedSetFor } from '../lib/domain-variant.ts'
import { gradeRun } from '../lib/grader.ts'
import { scanTreeForLeakage } from '../lib/materialize.ts'
import { assertLocalLabAllowed } from '../lib/safety.ts'
import type {
  BenchMode, Briefing, ChainSpec, Finding, GroundTruth, LabMode, OracleExport, SeedSet, TwinSpec,
} from '../lib/types.ts'
import { PAYGRID_CHAINS, PAYGRID_TWINS, startPaygrid } from '../apps/paygrid/index.ts'
import type { StartedPaygrid } from '../apps/paygrid/index.ts'
import { runReferenceSolvers as runPaygridSolvers } from '../apps/paygrid/solvers/index.ts'
import { SHIPFORGE_CHAINS, SHIPFORGE_TWINS, startShipforge } from '../apps/shipforge/index.ts'
import type { StartedShipforge } from '../apps/shipforge/index.ts'
import { runReferenceSolvers as runShipforgeSolvers } from '../apps/shipforge/solvers/index.ts'
import { NEXUSIAM_CHAINS, NEXUSIAM_TWINS, startNexusiam } from '../apps/nexusiam/index.ts'
import type { StartedNexusiam } from '../apps/nexusiam/index.ts'
import { runNexusiamSolvers } from '../apps/nexusiam/solvers/index.ts'
import { CONNECTHUB_CHAINS, CONNECTHUB_TWINS, startConnecthub } from '../apps/connecthub/index.ts'
import type { StartedConnecthub } from '../apps/connecthub/index.ts'
import { runReferenceSolvers as runConnecthubSolvers } from '../apps/connecthub/solvers/index.ts'

export const ALL_ARCHETYPES = ['paygrid', 'shipforge', 'nexusiam', 'connecthub'] as const
export type ArchetypeName = (typeof ALL_ARCHETYPES)[number]

const SCANNED_EXTS = new Set(['.ts', '.js', '.mjs', '.json', '.md', '.html'])
const ALL_ARCHETYPE_MARKERS = /(?:PG|SF|NX|CH)-[CD]\d/i

interface StartedArchetypeLab {
  app: string
  seed: number
  seedSet: SeedSet
  groundTruth: GroundTruth
  oracle: ChainOracle
  sourceDir: string
  sourceRoot?: string
  briefing(mode: BenchMode): Briefing
  export(): OracleExport
  stop(): Promise<void>
}

interface ArchetypeStartOptions {
  seed: number
  heldOutSalt?: string
  mode: LabMode
  twin?: string
  asyncLatencyMs?: number
}

interface ArchetypeAdapter {
  name: ArchetypeName
  chains: readonly ChainSpec[]
  twins: readonly TwinSpec[]
  start(options: ArchetypeStartOptions): Promise<StartedArchetypeLab>
  solve(lab: StartedArchetypeLab, chainIds?: readonly string[]): Promise<Finding[]>
}

const ARCHETYPE_ADAPTERS: Record<ArchetypeName, ArchetypeAdapter> = {
  paygrid: {
    name: 'paygrid',
    chains: PAYGRID_CHAINS,
    twins: PAYGRID_TWINS,
    start: (options) => startPaygrid(options),
    solve: (lab, chainIds) => runPaygridSolvers(lab as StartedPaygrid, chainIds),
  },
  shipforge: {
    name: 'shipforge',
    chains: SHIPFORGE_CHAINS,
    twins: SHIPFORGE_TWINS,
    start: (options) => startShipforge(options),
    solve: (lab, chainIds) => runShipforgeSolvers(lab as StartedShipforge, chainIds),
  },
  nexusiam: {
    name: 'nexusiam',
    chains: NEXUSIAM_CHAINS,
    twins: NEXUSIAM_TWINS,
    start: (options) => startNexusiam(options),
    solve: (lab, chainIds) => runNexusiamSolvers(lab as StartedNexusiam, chainIds),
  },
  connecthub: {
    name: 'connecthub',
    chains: CONNECTHUB_CHAINS,
    twins: CONNECTHUB_TWINS,
    start: (options) => startConnecthub(options),
    solve: (lab, chainIds) => runConnecthubSolvers(lab as StartedConnecthub, chainIds),
  },
}

export interface SweepOptions {
  apps?: readonly ArchetypeName[]
  devSeeds?: readonly number[]
  heldOutSeeds?: readonly number[]
  heldOutSalt?: string
  asyncLatencyMs?: number
  concurrency?: number
}

export interface SweepFailure {
  app: ArchetypeName
  seed: number
  seedSet: SeedSet
  scope: 'vulnerable' | 'hardened' | 'twin' | 'leakage'
  chainId?: string
  twinId?: string
  reason: string
}

export interface ArchetypeSeedResult {
  app: ArchetypeName
  seed: number
  seedSet: SeedSet
  vulnerablePassed: number
  vulnerableTotal: number
  receiptsVerified: number
  hardenedFindings: number
  hardenedOracleEvents: number
  hardenedPassed: boolean
  twinsPassed: number
  twinsTotal: number
  twinFindings: number
  twinTerminalEvents: number
  leakageHits: number
  durationMs: number
  failures: SweepFailure[]
}

export interface ArchetypeAggregate {
  app: ArchetypeName
  seedsTested: number
  devSeedsTested: number
  heldOutSeedsTested: number
  vulnerablePassed: number
  vulnerableTotal: number
  receiptsVerified: number
  hardenedFailures: number
  hardenedOracleEvents: number
  twinsPassed: number
  twinsTotal: number
  twinFailures: number
  twinTerminalEvents: number
  leakageHits: number
  pass: boolean
}

export interface SoundnessSweepReport {
  generatedAt: string
  apps: ArchetypeName[]
  devSeeds: number[]
  heldOutSeeds: number[]
  asyncLatencyMs: number
  durationMs: number
  totals: {
    cells: number
    vulnerablePassed: number
    vulnerableTotal: number
    receiptsVerified: number
    hardenedFailures: number
    hardenedOracleEvents: number
    twinsPassed: number
    twinsTotal: number
    twinFailures: number
    twinTerminalEvents: number
    leakageHits: number
    failureCount: number
  }
  byApp: ArchetypeAggregate[]
  cells: ArchetypeSeedResult[]
  failures: SweepFailure[]
  pass: boolean
}

export interface ParsedCliArgs {
  apps: ArchetypeName[]
  devSeeds: number[]
  heldOutSeeds: number[]
  asyncLatencyMs: number
  concurrency: number
  outPath?: string
  jsonStdout: boolean
}

function walkFiles(dir: string, visit: (file: string) => void): void {
  if (!existsSync(dir)) return
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) walkFiles(full, visit)
    else if (entry.isFile()) visit(full)
  }
}

/**
 * Full white-box leakage scan combining `scanTreeForLeakage` with an explicit check for
 * chain/twin ID markers across all 4 archetypes (PG/SF/NX/CH).
 */
export function scanMaterializedTree(root: string): string[] {
  const problems = new Set<string>(scanTreeForLeakage(root))
  walkFiles(root, (file) => {
    if (!SCANNED_EXTS.has(extname(file))) return
    const content = readFileSync(file, 'utf8')
    const match = ALL_ARCHETYPE_MARKERS.exec(content)
    if (match) problems.add(`leaky archetype marker '${match[0]}' in: ${file}`)
  })
  return [...problems]
}

function resolveMaterializedRoot(lab: StartedArchetypeLab): string {
  return lab.sourceRoot ?? join(lab.sourceDir, '..', '..', '..')
}

function totalOracleEvents(exported: OracleExport): number {
  return exported.events.hops.length +
    exported.events.edges.length +
    exported.events.controls.length +
    exported.events.terminals.length
}

async function runCell(
  adapter: ArchetypeAdapter,
  seed: number,
  options: { heldOutSalt?: string; asyncLatencyMs: number },
): Promise<ArchetypeSeedResult> {
  const startedAt = Date.now()
  const seedSet = seedSetFor(seed)
  const failures: SweepFailure[] = []
  const expectedChainIds = adapter.chains.map((chain) => chain.id)
  let vulnerablePassed = 0
  let receiptsVerified = 0
  let leakageHits = 0
  let hardenedFindings = 0
  let hardenedOracleEvents = 0
  let hardenedPassed = false
  let twinsPassed = 0
  let twinFindings = 0
  let twinTerminalEvents = 0

  // 1. Vulnerable mode (4/4 chains + Mode-A CompositeProofReceipt) + white-box leakage scan.
  const vulnLab = await adapter.start({
    seed,
    heldOutSalt: options.heldOutSalt,
    mode: 'vulnerable',
    asyncLatencyMs: options.asyncLatencyMs,
  })
  try {
    const root = resolveMaterializedRoot(vulnLab)
    const leakageProblems = scanMaterializedTree(root)
    leakageHits = leakageProblems.length
    for (const problem of leakageProblems) {
      failures.push({ app: adapter.name, seed, seedSet, scope: 'leakage', reason: problem })
    }

    const white = vulnLab.briefing('white-box')
    const grey = vulnLab.briefing('grey-box')
    const black = vulnLab.briefing('black-box')
    if (white.sourceDir !== vulnLab.sourceDir || grey.sourceDir !== undefined || black.sourceDir !== undefined) {
      leakageHits += 1
      failures.push({
        app: adapter.name,
        seed,
        seedSet,
        scope: 'leakage',
        reason: 'briefing mode sourceDir isolation mismatch',
      })
    }

    const findings = await adapter.solve(vulnLab)
    const exported = vulnLab.export()
    const card = gradeRun({ groundTruth: vulnLab.groundTruth, findings, oracle: exported })

    const confirmedById = new Map(exported.confirmed.map((item) => [item.chainId, item]))
    const evalById = new Map(exported.evaluations.map((item) => [item.chainId, item]))
    const findingById = new Map(findings.map((item) => [item.chainId, item]))

    for (const chainSpec of adapter.chains) {
      const chainId = chainSpec.id
      const finding = findingById.get(chainId)
      const confirmed = confirmedById.get(chainId)
      const evaluation = evalById.get(chainId)

      if (!finding) {
        failures.push({
          app: adapter.name,
          seed,
          seedSet,
          scope: 'vulnerable',
          chainId,
          reason: `solver returned no finding (${evaluation?.failureReason ?? 'missing'})`,
        })
        continue
      }
      if (!evaluation?.completed || !evaluation.confirmed || !evaluation.terminalObserved || !evaluation.receiptVerified) {
        failures.push({
          app: adapter.name,
          seed,
          seedSet,
          scope: 'vulnerable',
          chainId,
          reason: `ChainOracle v2 incomplete: ${evaluation?.failureReason ?? 'unconfirmed'}`,
        })
        continue
      }
      if (!confirmed || !confirmed.receiptVerified) {
        failures.push({
          app: adapter.name,
          seed,
          seedSet,
          scope: 'vulnerable',
          chainId,
          reason: 'missing confirmed entry in oracle export',
        })
        continue
      }
      const receipt = confirmed.receipt
      const check = vulnLab.oracle.verifyReceipt(receipt)
      const modeAOk = receipt.replayMode === 'fresh_clean_replay' &&
        receipt.signer === 'mh_host_runtime' &&
        receipt.signature.length > 0 &&
        receipt.hops.length === chainSpec.hops.length &&
        receipt.causalEdges.length === chainSpec.hops.length - 1
      if (!check.ok || !modeAOk) {
        failures.push({
          app: adapter.name,
          seed,
          seedSet,
          scope: 'vulnerable',
          chainId,
          reason: `Mode-A CompositeProofReceipt invalid: ${check.reason} (replayMode=${receipt.replayMode})`,
        })
        continue
      }
      receiptsVerified += 1
      if (card.matchedChainIds.includes(chainId)) {
        vulnerablePassed += 1
      } else {
        failures.push({
          app: adapter.name,
          seed,
          seedSet,
          scope: 'vulnerable',
          chainId,
          reason: 'chain not matched by grader',
        })
      }
    }

    if (
      findings.length !== expectedChainIds.length ||
      exported.events.terminals.length !== expectedChainIds.length ||
      card.fp !== 0 ||
      card.fn !== 0 ||
      card.precision !== 1 ||
      card.recall !== 1 ||
      !card.gate.pass
    ) {
      failures.push({
        app: adapter.name,
        seed,
        seedSet,
        scope: 'vulnerable',
        reason: `grader gate failed: tp=${card.tp} fp=${card.fp} fn=${card.fn} terminals=${exported.events.terminals.length}`,
      })
    }
  } finally {
    await vulnLab.stop()
  }

  // 2. Hardened mode: 0 findings and 0 oracle events across all 4 solvers.
  const hardenedLab = await adapter.start({
    seed,
    heldOutSalt: options.heldOutSalt,
    mode: 'hardened',
    asyncLatencyMs: options.asyncLatencyMs,
  })
  try {
    const findings = await adapter.solve(hardenedLab)
    const exported = hardenedLab.export()
    const card = gradeRun({ groundTruth: hardenedLab.groundTruth, findings, oracle: exported })
    hardenedFindings = findings.length
    hardenedOracleEvents = totalOracleEvents(exported)
    const anyObserved = exported.evaluations.some((ev) => ev.hopsObserved > 0 || ev.confirmed)
    hardenedPassed = hardenedFindings === 0 &&
      hardenedOracleEvents === 0 &&
      exported.confirmed.length === 0 &&
      !anyObserved &&
      card.fp === 0 &&
      card.precision === 1 &&
      card.gate.pass
    if (!hardenedPassed) {
      failures.push({
        app: adapter.name,
        seed,
        seedSet,
        scope: 'hardened',
        reason: `hardened silence violated: findings=${hardenedFindings} events=${hardenedOracleEvents} confirmed=${exported.confirmed.length}`,
      })
    }
  } finally {
    await hardenedLab.stop()
  }

  // 3. Partial-hop twins: real early hops (>=2), 0 findings, 0 terminal oracle events.
  for (const twin of adapter.twins) {
    const twinLab = await adapter.start({
      seed,
      heldOutSalt: options.heldOutSalt,
      mode: 'vulnerable',
      twin: twin.id,
      asyncLatencyMs: options.asyncLatencyMs,
    })
    try {
      const findings = await adapter.solve(twinLab, [twin.baseChainId])
      const exported = twinLab.export()
      const evaluation = twinLab.oracle.evaluate(twin.baseChainId)
      const card = gradeRun({ groundTruth: twinLab.groundTruth, findings, oracle: exported })
      const terminals = exported.events.terminals.length
      twinFindings += findings.length
      twinTerminalEvents += terminals
      const twinOk = findings.length === 0 &&
        terminals === 0 &&
        !evaluation.terminalObserved &&
        !evaluation.confirmed &&
        evaluation.hopsObserved >= 2 &&
        exported.events.hops.length >= 2 &&
        card.fp === 0 &&
        card.strictDecoyFps === 0 &&
        card.precision === 1 &&
        card.gate.pass
      if (twinOk) {
        twinsPassed += 1
      } else {
        failures.push({
          app: adapter.name,
          seed,
          seedSet,
          scope: 'twin',
          chainId: twin.baseChainId,
          twinId: twin.id,
          reason: `twin silence/exercise failed: findings=${findings.length} terminals=${terminals} hops=${evaluation.hopsObserved} confirmed=${evaluation.confirmed}`,
        })
      }
    } finally {
      await twinLab.stop()
    }
  }

  return {
    app: adapter.name,
    seed,
    seedSet,
    vulnerablePassed,
    vulnerableTotal: adapter.chains.length,
    receiptsVerified,
    hardenedFindings,
    hardenedOracleEvents,
    hardenedPassed,
    twinsPassed,
    twinsTotal: adapter.twins.length,
    twinFindings,
    twinTerminalEvents,
    leakageHits,
    durationMs: Date.now() - startedAt,
    failures,
  }
}

async function runPool<T, R>(
  items: readonly T[],
  concurrency: number,
  worker: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length)
  let nextIndex = 0
  const workers = Array.from({ length: Math.min(Math.max(1, concurrency), items.length) }, async () => {
    while (true) {
      const index = nextIndex
      nextIndex += 1
      if (index >= items.length) break
      results[index] = await worker(items[index]!)
    }
  })
  await Promise.all(workers)
  return results
}

export async function runSoundnessSweep(options: SweepOptions = {}): Promise<SoundnessSweepReport> {
  assertLocalLabAllowed()
  const startedAt = Date.now()
  const apps: ArchetypeName[] = options.apps ? [...options.apps] : [...ALL_ARCHETYPES]
  const devSeeds: number[] = options.devSeeds ? [...options.devSeeds] : Array.from({ length: 30 }, (_, i) => i + 1)
  const heldOutSeeds: number[] = options.heldOutSeeds ? [...options.heldOutSeeds] : []
  const asyncLatencyMs = options.asyncLatencyMs ?? 5
  const concurrency = options.concurrency ?? 4

  if (devSeeds.length === 0 && heldOutSeeds.length === 0) {
    throw new Error('soundness-sweep requires at least one dev or held-out seed')
  }
  for (const seed of devSeeds) {
    if (seedSetFor(seed) !== 'dev') throw new Error(`expected dev seed (1..9999), got ${seed}`)
  }
  let resolvedSalt: string | undefined
  if (heldOutSeeds.length > 0) {
    resolvedSalt = requireHeldOutSalt(options.heldOutSalt)
    for (const seed of heldOutSeeds) {
      if (seedSetFor(seed) !== 'held-out') throw new Error(`expected held-out seed (>=${HELDOUT_MIN}), got ${seed}`)
    }
  }

  const allSeeds = [...devSeeds, ...heldOutSeeds]
  const tasks: Array<{ app: ArchetypeName; seed: number }> = []
  for (const seed of allSeeds) {
    for (const app of apps) {
      tasks.push({ app, seed })
    }
  }

  const cells = await runPool(tasks, concurrency, ({ app, seed }) =>
    runCell(ARCHETYPE_ADAPTERS[app], seed, {
      heldOutSalt: seedSetFor(seed) === 'held-out' ? resolvedSalt : undefined,
      asyncLatencyMs,
    }))

  const byApp: ArchetypeAggregate[] = apps.map((app) => {
    const appCells = cells.filter((cell) => cell.app === app)
    const vulnerablePassed = appCells.reduce((acc, cell) => acc + cell.vulnerablePassed, 0)
    const vulnerableTotal = appCells.reduce((acc, cell) => acc + cell.vulnerableTotal, 0)
    const receiptsVerified = appCells.reduce((acc, cell) => acc + cell.receiptsVerified, 0)
    const hardenedFailures = appCells.filter((cell) => !cell.hardenedPassed).length
    const hardenedOracleEvents = appCells.reduce((acc, cell) => acc + cell.hardenedOracleEvents, 0)
    const twinsPassed = appCells.reduce((acc, cell) => acc + cell.twinsPassed, 0)
    const twinsTotal = appCells.reduce((acc, cell) => acc + cell.twinsTotal, 0)
    const twinFailures = twinsTotal - twinsPassed
    const twinTerminalEvents = appCells.reduce((acc, cell) => acc + cell.twinTerminalEvents, 0)
    const leakageHits = appCells.reduce((acc, cell) => acc + cell.leakageHits, 0)
    const appFailureCount = appCells.reduce((acc, cell) => acc + cell.failures.length, 0)
    return {
      app,
      seedsTested: appCells.length,
      devSeedsTested: appCells.filter((cell) => cell.seedSet === 'dev').length,
      heldOutSeedsTested: appCells.filter((cell) => cell.seedSet === 'held-out').length,
      vulnerablePassed,
      vulnerableTotal,
      receiptsVerified,
      hardenedFailures,
      hardenedOracleEvents,
      twinsPassed,
      twinsTotal,
      twinFailures,
      twinTerminalEvents,
      leakageHits,
      pass: appFailureCount === 0 &&
        vulnerablePassed === vulnerableTotal &&
        receiptsVerified === vulnerableTotal &&
        hardenedFailures === 0 &&
        hardenedOracleEvents === 0 &&
        twinFailures === 0 &&
        twinTerminalEvents === 0 &&
        leakageHits === 0,
    }
  })

  const failures = cells.flatMap((cell) => cell.failures)
  const totals = {
    cells: cells.length,
    vulnerablePassed: byApp.reduce((acc, row) => acc + row.vulnerablePassed, 0),
    vulnerableTotal: byApp.reduce((acc, row) => acc + row.vulnerableTotal, 0),
    receiptsVerified: byApp.reduce((acc, row) => acc + row.receiptsVerified, 0),
    hardenedFailures: byApp.reduce((acc, row) => acc + row.hardenedFailures, 0),
    hardenedOracleEvents: byApp.reduce((acc, row) => acc + row.hardenedOracleEvents, 0),
    twinsPassed: byApp.reduce((acc, row) => acc + row.twinsPassed, 0),
    twinsTotal: byApp.reduce((acc, row) => acc + row.twinsTotal, 0),
    twinFailures: byApp.reduce((acc, row) => acc + row.twinFailures, 0),
    twinTerminalEvents: byApp.reduce((acc, row) => acc + row.twinTerminalEvents, 0),
    leakageHits: byApp.reduce((acc, row) => acc + row.leakageHits, 0),
    failureCount: failures.length,
  }

  const pass = failures.length === 0 && byApp.every((row) => row.pass)
  return {
    generatedAt: new Date().toISOString(),
    apps,
    devSeeds,
    heldOutSeeds,
    asyncLatencyMs,
    durationMs: Date.now() - startedAt,
    totals,
    byApp,
    cells,
    failures,
    pass,
  }
}

export function renderSoundnessReport(report: SoundnessSweepReport, format: 'json' | 'md'): string {
  if (format === 'json') return `${JSON.stringify(report, null, 2)}\n`

  const seedRange = (seeds: readonly number[]): string => {
    if (seeds.length === 0) return 'none'
    const first = seeds[0]!
    const last = seeds[seeds.length - 1]!
    const contiguous = seeds.every((value, idx) => value === first + idx)
    return contiguous ? `${first}..${last} (${seeds.length})` : `${seeds.join(',')} (${seeds.length})`
  }

  const lines = [
    '# multihop-saas Soundness & Leakage Sweep Report',
    '',
    `- Status: **${report.pass ? 'PASS' : 'FAIL'}**`,
    `- Archetypes: ${report.apps.join(', ')}`,
    `- Dev seeds: ${seedRange(report.devSeeds)}`,
    `- Held-out seeds: ${seedRange(report.heldOutSeeds)}`,
    `- Vulnerable chains: ${report.totals.vulnerablePassed}/${report.totals.vulnerableTotal} (Mode-A receipts verified: ${report.totals.receiptsVerified}/${report.totals.vulnerableTotal})`,
    `- Hardened silence: ${report.totals.hardenedFailures} failures (${report.totals.hardenedOracleEvents} oracle events)`,
    `- Partial-hop twins: ${report.totals.twinsPassed}/${report.totals.twinsTotal} silent (${report.totals.twinFailures} failures, ${report.totals.twinTerminalEvents} terminal events)`,
    `- White-box leakage scan: ${report.totals.leakageHits} hits`,
    `- Duration: ${(report.durationMs / 1000).toFixed(2)}s`,
    '',
    '## Per-Archetype Summary',
    '',
    '| Archetype | Seeds | Vulnerable | Receipts | Hardened Fails | Twins Silent | Leakage Hits | Status |',
    '|---|---:|---:|---:|---:|---:|---:|---|',
    ...report.byApp.map((row) =>
      `| ${row.app} | ${row.seedsTested} | ${row.vulnerablePassed}/${row.vulnerableTotal} | ${row.receiptsVerified}/${row.vulnerableTotal} | ${row.hardenedFailures} | ${row.twinsPassed}/${row.twinsTotal} | ${row.leakageHits} | ${row.pass ? 'PASS' : 'FAIL'} |`),
    '',
  ]

  if (report.failures.length > 0) {
    lines.push('## Failures', '')
    for (const failure of report.failures) {
      const target = [failure.chainId, failure.twinId].filter(Boolean).join('/')
      lines.push(
        `- \`${failure.app}\` seed=${failure.seed} (${failure.seedSet}) [${failure.scope}${target ? ` ${target}` : ''}]: ${failure.reason}`,
      )
    }
    lines.push('')
  }

  return lines.join('\n')
}

function parseSeedSpec(raw: string, baseStart: number): number[] {
  if (raw.includes(',')) {
    const parsed = raw.split(',').map((part) => Number(part.trim()))
    if (parsed.length === 0 || parsed.some((value) => !Number.isInteger(value))) {
      throw new Error(`invalid seed list '${raw}'`)
    }
    return parsed
  }
  const count = Number(raw)
  if (!Number.isInteger(count) || count < 0) {
    throw new Error(`invalid seed count '${raw}': expected non-negative integer`)
  }
  return Array.from({ length: count }, (_, idx) => baseStart + idx)
}

export function parseSweepCliArgs(argv: readonly string[]): ParsedCliArgs {
  const flags: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!
    if (!arg.startsWith('--')) continue
    const key = arg.slice(2)
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) {
      flags[key] = true
    } else {
      flags[key] = next
      i += 1
    }
  }

  if (flags['held-out-salt'] !== undefined || flags.salt !== undefined) {
    throw new Error('never pass the held-out salt on the command line; set GUARDIAN_RB_HELDOUT_SALT instead')
  }

  let apps: ArchetypeName[] = [...ALL_ARCHETYPES]
  if (typeof flags.apps === 'string') {
    const requested = flags.apps.split(',').map((value) => value.trim()).filter(Boolean)
    if (requested.length === 0) throw new Error('--apps must list at least one archetype')
    for (const item of requested) {
      if (!(ALL_ARCHETYPES as readonly string[]).includes(item)) {
        throw new Error(`unknown archetype '${item}': expected one of ${ALL_ARCHETYPES.join(', ')}`)
      }
    }
    apps = requested as ArchetypeName[]
  }

  const noDev = flags['no-dev'] === true
  const devSeeds = noDev
    ? []
    : parseSeedSpec(typeof flags.seeds === 'string' ? flags.seeds : '30', 1)

  let heldOutSeeds: number[] = []
  if (flags['held-out'] !== undefined || flags['held-out-seeds'] !== undefined) {
    const rawHeldOut = typeof flags['held-out-seeds'] === 'string'
      ? flags['held-out-seeds']
      : typeof flags['held-out'] === 'string'
        ? flags['held-out']
        : '5'
    heldOutSeeds = parseSeedSpec(rawHeldOut, HELDOUT_MIN + 1)
  }

  const asyncLatencyMs = flags['async-latency-ms'] !== undefined ? Number(flags['async-latency-ms']) : 5
  if (!Number.isFinite(asyncLatencyMs) || asyncLatencyMs < 0) {
    throw new Error('--async-latency-ms must be a non-negative number')
  }

  const concurrency = flags.concurrency !== undefined ? Number(flags.concurrency) : 4
  if (!Number.isInteger(concurrency) || concurrency < 1) {
    throw new Error('--concurrency must be a positive integer')
  }

  const outPath = typeof flags.out === 'string' ? flags.out : undefined
  const jsonStdout = flags.json === true

  return { apps, devSeeds, heldOutSeeds, asyncLatencyMs, concurrency, outPath, jsonStdout }
}

function writeReportArtifacts(outPath: string, report: SoundnessSweepReport): { jsonPath: string; mdPath: string } {
  const abs = isAbsolute(outPath) ? outPath : resolve(process.cwd(), outPath)
  let jsonPath: string
  let mdPath: string
  if (abs.endsWith('.json')) {
    jsonPath = abs
    mdPath = `${abs.slice(0, -5)}.md`
  } else if (abs.endsWith('.md')) {
    mdPath = abs
    jsonPath = `${abs.slice(0, -3)}.json`
  } else {
    jsonPath = `${abs}.json`
    mdPath = `${abs}.md`
  }
  mkdirSync(dirname(jsonPath), { recursive: true })
  writeFileSync(jsonPath, renderSoundnessReport(report, 'json'))
  writeFileSync(mdPath, renderSoundnessReport(report, 'md'))
  return { jsonPath, mdPath }
}

async function main(): Promise<void> {
  const parsed = parseSweepCliArgs(process.argv.slice(2))
  const report = await runSoundnessSweep({
    apps: parsed.apps,
    devSeeds: parsed.devSeeds,
    heldOutSeeds: parsed.heldOutSeeds,
    asyncLatencyMs: parsed.asyncLatencyMs,
    concurrency: parsed.concurrency,
  })
  if (parsed.outPath) {
    const written = writeReportArtifacts(parsed.outPath, report)
    process.stderr.write(`[soundness-sweep] wrote ${written.jsonPath} and ${written.mdPath}\n`)
  }
  process.stdout.write(renderSoundnessReport(report, parsed.jsonStdout ? 'json' : 'md'))
  if (!report.pass) process.exit(2)
}

const isEntrypoint = process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (isEntrypoint) {
  main().catch((err: unknown) => {
    process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`)
    process.exit(1)
  })
}
