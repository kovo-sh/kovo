// reason-bench entrypoint: programmatic API + CLI.
//   startReasonApp({ app, seed }) -> StartedApp     (boots a per-seed loopback lab)
//   briefingFor(app, mode)                          (what a scanner may see, per mode)
//   gradeRun(input) / renderScorecard(...)           (re-exported from grader/)
//   listSeeds(set, n)
// CLI: serve | grade | selftest | seeds | anti-heuristic-check
//
// Apps are imported lazily by name from apps/<app>/index.ts so this file typechecks and runs before
// the app shells exist. `listSeeds` is intentionally stricter than realistic-bench: the held-out
// salt is only read from GUARDIAN_RB_HELDOUT_SALT, never from a CLI flag.
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs'
import { join, dirname, isAbsolute, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type {
  AppName, AppModule, BenchMode, Briefing, SeedSet, StartedApp, VariantPlan, GroundTruth, ApiRef,
  GradeInput, Scorecard,
} from './lib/types.ts'
import { appNames } from './lib/types.ts'
import { assertLocalLabAllowed } from './lib/safety.ts'
import { resolveSeed, listSeeds as genListSeeds } from './generator/seeds.ts'
import { validateBlueprint } from './generator/validate.ts'
import { generateVariant } from './generator/variant.ts'
import { buildGroundTruth } from './generator/groundtruth.ts'
import { gradeRun, ANTI_HEURISTIC_FLOOR_MAX } from './grader/score.ts'
import { renderScorecard } from './grader/report.ts'
import { validateGradeInput } from './grader/schema.ts'

export { gradeRun, renderScorecard, ANTI_HEURISTIC_FLOOR_MAX }
export const listSeeds = genListSeeds

const HERE = dirname(fileURLToPath(import.meta.url))
export const APPS_ROOT = join(HERE, 'apps')

function isApp(x: string): x is AppName {
  return (appNames as readonly string[]).includes(x)
}

async function loadModule(app: AppName): Promise<AppModule> {
  const file = join(APPS_ROOT, app, 'index.ts')
  let mod: { default?: AppModule }
  try {
    mod = (await import(pathToFileURL(file).href)) as { default?: AppModule }
  } catch (err) {
    throw new Error(`app '${app}' is not available yet (${join('apps', app, 'index.ts')}): ${(err as Error).message}`)
  }
  const loaded = mod.default
  if (!loaded || loaded.name !== app) {
    throw new Error(`apps/${app}/index.ts must default-export an AppModule named '${app}'`)
  }
  if (loaded.reasonBench !== true) {
    throw new Error(`apps/${app}/index.ts must set reasonBench: true on its AppModule`)
  }
  return loaded
}

export interface StartOpts {
  app: AppName
  seed: number
  heldOutSalt?: string
  oobCallbackPorts?: number[]
}

export async function startReasonApp(opts: StartOpts): Promise<StartedApp> {
  assertLocalLabAllowed()
  if (!isApp(opts.app)) throw new Error(`unknown app '${opts.app}'. Known: ${appNames.join(', ')}`)
  const mod = await loadModule(opts.app)
  const blueprint = validateBlueprint(mod.blueprint)
  const resolved = resolveSeed(opts.seed, opts.heldOutSalt)
  const plan: VariantPlan = generateVariant(blueprint, opts.seed, { salt: opts.heldOutSalt })
  plan.seedSet = resolved.seedSet
  const groundTruth: GroundTruth = buildGroundTruth(blueprint, plan)
  return mod.start({ plan, groundTruth, oobCallbackPorts: opts.oobCallbackPorts })
}

function apiReference(plan: VariantPlan): ApiRef[] {
  return Object.entries(plan.routes).map(([routeKey, r]) => {
    const pathParams = (r.path.match(/:([a-zA-Z0-9_]+)/g) ?? []).map((s) => s.slice(1))
    return { routeKey, method: r.method, path: r.path, params: pathParams }
  })
}

/** Briefing by mode: black-box => member_a + member_b; grey-box => all six + API ref; white-box => + sourceDir. */
export function briefingFor(app: StartedApp, mode: BenchMode): Briefing {
  const all = Object.values(app.plan.personas).map((p) => ({
    id: p.id, email: p.email, password: p.password, tenant: p.tenant, role: p.role,
  }))
  const visible = mode === 'black-box'
    ? all.filter((p) => p.id === 'member_a' || p.id === 'member_b')
    : all
  const briefing: Briefing = { app: app.app, mode, origin: app.origin, personas: visible }
  if (mode === 'grey-box' || mode === 'white-box') briefing.apiReference = apiReference(app.plan)
  if (mode === 'white-box') briefing.sourceDir = app.sourceDir
  return briefing
}

// ---------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------
function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!
    if (a.startsWith('--')) {
      const key = a.slice(2)
      const next = argv[i + 1]
      if (next === undefined || next.startsWith('--')) out[key] = true
      else { out[key] = next; i++ }
    }
  }
  return out
}

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(isAbsolute(path) ? path : resolve(process.cwd(), path), 'utf8')) as T
}

function gradeInputFromArgs(a: Record<string, string | boolean>): GradeInput {
  return {
    groundTruth: readJson(String(a.truth)),
    findings: readJson(String(a.findings)),
    oracleEvents: readJson(String(a.events)),
    requestLog: readJson(String(a.requests)),
    egressLog: a.egress ? readJson(String(a.egress)) : [],
    telemetry: readJson(String(a.telemetry)),
    mode: (a.mode ? String(a.mode) : 'black-box') as BenchMode,
    heuristicFloor: a['heuristic-floor'] != null ? Number(a['heuristic-floor']) : undefined,
  }
}

async function cmdServe(a: Record<string, string | boolean>): Promise<void> {
  const app = String(a.app ?? '')
  const seed = Number(a.seed ?? 1)
  const mode = (a.mode ? String(a.mode) : 'grey-box') as BenchMode
  const outDir = String(a['out-dir'] ?? join(HERE, 'out'))
  if (!isApp(app)) throw new Error(`--app must be one of ${appNames.join(', ')}`)
  if (a['held-out-salt'] !== undefined) {
    throw new Error('never pass the held-out salt on the command line; set GUARDIAN_RB_HELDOUT_SALT instead')
  }
  const started = await startReasonApp({ app, seed })
  const briefing = briefingFor(started, mode)
  process.stdout.write(`${JSON.stringify(briefing, null, 2)}\n`)
  const dump = (): void => {
    mkdirSync(outDir, { recursive: true })
    const base = join(outDir, `${app}-${seed}`)
    writeFileSync(`${base}.groundtruth.json`, JSON.stringify(started.groundTruth, null, 2))
    writeFileSync(`${base}.oracle-events.json`, JSON.stringify(started.oracle.events(), null, 2))
    writeFileSync(`${base}.requests.json`, JSON.stringify(started.oracle.requests(), null, 2))
    writeFileSync(`${base}.egress.json`, JSON.stringify(started.oracle.egress(), null, 2))
    writeFileSync(`${base}.briefing.json`, JSON.stringify(briefing, null, 2))
  }
  const shutdown = async (): Promise<void> => {
    dump()
    await started.stop()
    process.exit(0)
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
  process.stderr.write(
    `[reason-bench] ${app} seed=${seed} (${started.plan.seedSet}) listening at ${started.origin} — ` +
      `Ctrl-C to stop (artifacts -> ${outDir})\n`,
  )
}

async function cmdGrade(a: Record<string, string | boolean>): Promise<void> {
  const input = gradeInputFromArgs(a)
  const check = validateGradeInput(input)
  if (!check.ok) throw new Error(`invalid grade input:\n${check.errors.join('\n')}`)
  const card = gradeRun(input)
  if (a.json) writeFileSync(String(a.json), renderScorecard(card, 'json'))
  if (a.md) writeFileSync(String(a.md), renderScorecard(card, 'md'))
  process.stdout.write(renderScorecard(card, a.md || a.json ? 'json' : 'md'))
}

/**
 * Anti-Heuristic Gate: the deterministic `--no-llm` run must score <= maxRecall (default 15%).
 * Accepts either a precomputed scorecard JSON or a full grade input. This is a measurement gate,
 * not a harness: M4 feeds it the real Execution --no-llm scorecard.
 */
async function cmdAntiHeuristicCheck(a: Record<string, string | boolean>): Promise<void> {
  const maxRecall = a['max-recall'] != null ? Number(a['max-recall']) : ANTI_HEURISTIC_FLOOR_MAX
  let card: Scorecard
  if (a.scorecard) {
    card = readJson<Scorecard>(String(a.scorecard))
  } else {
    const input = gradeInputFromArgs(a)
    const check = validateGradeInput(input)
    if (!check.ok) throw new Error(`invalid grade input:\n${check.errors.join('\n')}`)
    card = gradeRun(input)
  }
  const recall = card.recall
  const pass = recall <= maxRecall
  process.stdout.write(`${JSON.stringify({
    app: card.app, seed: card.seed, seedSet: card.seedSet, mode: card.mode,
    heuristicFloor: recall, maxRecall, pass,
  }, null, 2)}\n`)
  if (!pass) process.exit(2)
}

async function cmdSelftest(a: Record<string, string | boolean>): Promise<void> {
  const appArg = String(a.app ?? 'all')
  const apps = appArg === 'all' ? appNames.slice() : [appArg]
  const seeds = String(a.seeds ?? '1,2,3').split(',').map((s) => Number(s.trim())).filter((n) => Number.isFinite(n))
  let anyFail = false
  for (const app of apps) {
    if (!isApp(app)) throw new Error(`--app must be one of ${appNames.join(', ')} or 'all'`)
    let selftest: { runSiteMatrix?: (o: { seeds: number[]; siteIds?: string[] }) => Promise<SelftestResult> }
    try {
      selftest = (await import(pathToFileURL(join(APPS_ROOT, app, 'truth', 'selftest.ts')).href)) as typeof selftest
    } catch {
      process.stdout.write(`[${app}] no selftest available\n`)
      continue
    }
    if (!selftest.runSiteMatrix) { process.stdout.write(`[${app}] selftest has no runSiteMatrix\n`); continue }
    const result = await selftest.runSiteMatrix({ seeds })
    process.stdout.write(`[${app}] ${result.summary}\n`)
    for (const row of result.rows) {
      if (!row.ok) { anyFail = true; process.stdout.write(`  FAIL ${row.siteId} seed=${row.seed} mode=${row.mode}: ${row.detail}\n`) }
    }
  }
  if (anyFail) process.exit(2)
  process.stdout.write('selftest OK\n')
}

interface SelftestResult {
  summary: string
  rows: Array<{ siteId: string; seed: number; mode: 'vulnerable' | 'hardened'; ok: boolean; detail: string }>
}

function cmdSeeds(a: Record<string, string | boolean>): void {
  const set = (a.set ? String(a.set) : 'dev') as SeedSet
  const n = Number(a.n ?? 5)
  if (a.salt !== undefined) {
    throw new Error('never pass the held-out salt on the command line; set GUARDIAN_RB_HELDOUT_SALT instead')
  }
  process.stdout.write(`${JSON.stringify(genListSeeds(set, n))}\n`)
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2)
  const a = parseArgs(rest)
  switch (cmd) {
    case 'serve': return cmdServe(a)
    case 'grade': return cmdGrade(a)
    case 'selftest': return cmdSelftest(a)
    case 'seeds': return cmdSeeds(a)
    case 'anti-heuristic-check': return cmdAntiHeuristicCheck(a)
    default:
      process.stderr.write('usage: run.ts <serve|grade|selftest|seeds|anti-heuristic-check> [--flags]\n')
      process.exit(1)
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    process.stderr.write(`error: ${(err as Error).message}\n`)
    process.exit(1)
  })
}
