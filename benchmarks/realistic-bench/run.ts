// realistic-bench entrypoint: programmatic API + CLI.
//   startRealisticApp({ app, seed }) -> StartedApp   (boots a per-seed lab on 127.0.0.1)
//   briefingFor(app, mode)                            (what a scanner may see, per mode)
//   gradeRun(input) / renderScorecard(...)            (re-exported from grader/)
//   listSeeds(set, n)
// CLI: serve | grade | selftest | seeds
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs'
import { join, dirname, isAbsolute, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  AppName, AppModule, BenchMode, Briefing, SeedSet, StartedApp, VariantPlan, GroundTruth, ApiRef,
} from './lib/types.ts'
import { appNames } from './lib/types.ts'
import { assertLocalLabAllowed } from './lib/safety.ts'
import { resolveSeed, listSeeds as genListSeeds } from './generator/seeds.ts'
import { validateBlueprint } from './generator/validate.ts'
import { generateVariant } from './generator/variant.ts'
import { buildGroundTruth } from './generator/groundtruth.ts'
import { gradeRun } from './grader/score.ts'
import { renderScorecard } from './grader/report.ts'
import { validateGradeInput } from './grader/schema.ts'
import type { GradeInput } from './lib/types.ts'

export { gradeRun, renderScorecard }
export const listSeeds = genListSeeds

const HERE = dirname(fileURLToPath(import.meta.url))

function isApp(x: string): x is AppName {
  return (appNames as readonly string[]).includes(x)
}

async function loadModule(app: AppName): Promise<AppModule> {
  const path = join(HERE, 'apps', app, 'index.ts')
  let mod: { default?: AppModule }
  try {
    mod = await import(path)
  } catch (err) {
    throw new Error(`app '${app}' is not available yet (${join('apps', app, 'index.ts')}): ${(err as Error).message}`)
  }
  if (!mod.default || mod.default.name !== app) {
    throw new Error(`apps/${app}/index.ts must default-export an AppModule named '${app}'`)
  }
  return mod.default
}

export interface StartOpts {
  app: AppName
  seed: number
  heldOutSalt?: string
  oobCallbackPorts?: number[]
}

export async function startRealisticApp(opts: StartOpts): Promise<StartedApp> {
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
  const paramsByRoute = new Map<string, string[]>()
  // path params are visible from the route; field params are intentionally not exhaustively leaked
  return Object.entries(plan.routes).map(([routeKey, r]) => {
    const pathParams = (r.path.match(/:([a-zA-Z0-9_]+)/g) ?? []).map((s) => s.slice(1))
    return { routeKey, method: r.method, path: r.path, params: paramsByRoute.get(routeKey) ?? pathParams }
  })
}

export function briefingFor(app: StartedApp, mode: BenchMode): Briefing {
  const personas = Object.values(app.plan.personas).map((p) => ({
    id: p.id, email: p.email, password: p.password, tenant: p.tenant, role: p.role,
  }))
  const visible = mode === 'black-box'
    ? personas.filter((p) => p.id === 'persona_a' || p.id === 'persona_b')
    : personas
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

async function cmdServe(a: Record<string, string | boolean>): Promise<void> {
  const app = String(a.app ?? '')
  const seed = Number(a.seed ?? 1)
  const mode = (a.mode ? String(a.mode) : 'grey-box') as BenchMode
  const outDir = String(a['out-dir'] ?? join(HERE, 'out'))
  if (!isApp(app)) throw new Error(`--app must be one of ${appNames.join(', ')}`)
  const salt = typeof a['held-out-salt'] === 'string' ? (a['held-out-salt'] as string) : undefined
  const started = await startRealisticApp({ app, seed, heldOutSalt: salt })
  const briefing = briefingFor(started, mode)
  process.stdout.write(`${JSON.stringify(briefing, null, 2)}\n`)
  const dump = () => {
    mkdirSync(outDir, { recursive: true })
    const base = join(outDir, `${app}-${seed}`)
    writeFileSync(`${base}.groundtruth.json`, JSON.stringify(started.groundTruth, null, 2))
    writeFileSync(`${base}.oracle-events.json`, JSON.stringify(started.oracle.events(), null, 2))
    writeFileSync(`${base}.requests.json`, JSON.stringify(started.oracle.requests(), null, 2))
    writeFileSync(`${base}.egress.json`, JSON.stringify(started.oracle.egress(), null, 2))
    writeFileSync(`${base}.briefing.json`, JSON.stringify(briefing, null, 2))
  }
  const shutdown = async () => {
    dump()
    await started.stop()
    process.exit(0)
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
  process.stderr.write(`[realistic-bench] ${app} seed=${seed} (${started.plan.seedSet}) listening at ${started.origin} — Ctrl-C to stop (artifacts -> ${outDir})\n`)
}

async function cmdGrade(a: Record<string, string | boolean>): Promise<void> {
  const input: GradeInput = {
    groundTruth: readJson(String(a.truth)),
    findings: readJson(String(a.findings)),
    oracleEvents: readJson(String(a.events)),
    requestLog: readJson(String(a.requests)),
    egressLog: a.egress ? readJson(String(a.egress)) : [],
    telemetry: readJson(String(a.telemetry)),
    mode: (a.mode ? String(a.mode) : 'black-box') as BenchMode,
  }
  const check = validateGradeInput(input)
  if (!check.ok) throw new Error(`invalid grade input:\n${check.errors.join('\n')}`)
  const card = gradeRun(input)
  if (a.json) writeFileSync(String(a.json), renderScorecard(card, 'json'))
  if (a.md) writeFileSync(String(a.md), renderScorecard(card, 'md'))
  process.stdout.write(renderScorecard(card, a.md || a.json ? 'json' : 'md'))
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
      selftest = await import(join(HERE, 'apps', app, 'truth', 'selftest.ts'))
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
  const salt = typeof a.salt === 'string' ? (a.salt as string) : undefined
  process.stdout.write(`${JSON.stringify(genListSeeds(set, n, salt))}\n`)
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2)
  const a = parseArgs(rest)
  switch (cmd) {
    case 'serve': return cmdServe(a)
    case 'grade': return cmdGrade(a)
    case 'selftest': return cmdSelftest(a)
    case 'seeds': return cmdSeeds(a)
    default:
      process.stderr.write('usage: run.ts <serve|grade|selftest|seeds> [--flags]\n')
      process.exit(1)
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    process.stderr.write(`error: ${(err as Error).message}\n`)
    process.exit(1)
  })
}
