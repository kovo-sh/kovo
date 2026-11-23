// Materialize a per-seed app tree for white-box mounting. Copies generic lib + app src/ui, lays down
// the chosen (vulnerable|hardened) site file at its neutral rootCause path, and writes
// variant.json / modules.json. App directories are discovered dynamically under apps/ so the
// harness compiles before any app shell exists and picks up new apps without edits.
import { randomBytes } from 'node:crypto'
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'
import type { AppBlueprint, AppName, VariantPlan } from '../lib/types.ts'
import { appDirFor } from './variant.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
export const DEFAULT_APPS_ROOT = join(HERE, '..', 'apps')
export const DEFAULT_LIB_DIR = join(HERE, '..', 'lib')

const BANNED = /vulnerab|hardened|decoy|oracle|solver|CWE-|ground.?truth/i

export interface MaterializeInput {
  blueprint: AppBlueprint
  plan: VariantPlan
  appDir?: string // explicit app shell dir; otherwise discovered under appsRoot/<app>
  appsRoot?: string // defaults to benchmarks/reason-bench/apps
  libDir?: string // defaults to benchmarks/reason-bench/lib
  uiSubdir?: string // defaults to 'ui'
  outRoot?: string // defaults to os.tmpdir()
}

export interface MaterializeResult {
  root: string
  sourceDir: string
  uiDir: string
  variantPath: string
  cleanup(): void
}

function walk(dir: string, visit: (file: string) => void): void {
  if (!existsSync(dir)) return
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) walk(full, visit)
    else if (entry.isFile()) visit(full)
  }
}

/** Every leakage problem under `root/apps` (content markers + forbidden truth/solver paths). */
export function scanTreeForLeakage(root: string): string[] {
  const appsDir = join(root, 'apps')
  const problems: string[] = []
  walk(appsDir, (file) => {
    const parts = file.split(sep)
    if (parts.includes('sites') || parts.includes('truth')) problems.push(`leaky path: ${file}`)
    if (parts[parts.length - 1] === 'solver.ts') problems.push(`leaky path: ${file}`)
    if (BANNED.test(readFileSync(file, 'utf8'))) problems.push(`leaky content in: ${file}`)
  })
  return problems
}

/** Fail if any app-tree file leaks truth: banned content, or a sites/truth/solver path. */
export function assertNoLeakage(root: string): void {
  const problems = scanTreeForLeakage(root)
  if (problems.length) throw new Error(`assertNoLeakage failed under ${join(root, 'apps')}:\n  - ${problems.join('\n  - ')}`)
}

/** Resolve the app shell directory, discovering it dynamically under appsRoot. */
export function resolveAppDir(app: AppName, opts: { appDir?: string; appsRoot?: string } = {}): string {
  if (opts.appDir) {
    if (!existsSync(join(opts.appDir, 'src'))) throw new Error(`materialize: no src/ under appDir ${opts.appDir}`)
    return opts.appDir
  }
  const found = appDirFor(opts.appsRoot ?? DEFAULT_APPS_ROOT, app)
  if (!found) {
    throw new Error(
      `materialize: app '${app}' is not built yet (no ${join(opts.appsRoot ?? DEFAULT_APPS_ROOT, app, 'index.ts')})`,
    )
  }
  return found
}

function assertVariantClean(variantPath: string): void {
  const raw = readFileSync(variantPath, 'utf8')
  const parsed = JSON.parse(raw) as Record<string, unknown>
  for (const key of ['sites', 'seedSet', 'personas', 'chains', 'causalChains']) {
    if (key in parsed) throw new Error(`materialize: variant.json must not expose '${key}'`)
  }
  if (BANNED.test(JSON.stringify(parsed))) throw new Error('materialize: variant.json contains a leakage marker')
}

export function materialize(input: MaterializeInput): MaterializeResult {
  const { blueprint: bp, plan } = input
  const app = plan.app
  const appDir = resolveAppDir(app, { appDir: input.appDir, appsRoot: input.appsRoot })
  const libDir = input.libDir ?? DEFAULT_LIB_DIR
  const root = join(input.outRoot ?? tmpdir(), 'reason-bench', `${app}-${plan.seed}-${randomBytes(4).toString('hex')}`)
  const appRoot = join(root, 'apps', app)
  const sourceDir = join(appRoot, 'src')

  mkdirSync(root, { recursive: true })
  cpSync(libDir, join(root, 'lib'), { recursive: true })
  cpSync(join(appDir, 'src'), sourceDir, { recursive: true })
  const uiDir = join(appDir, input.uiSubdir ?? 'ui')
  if (existsSync(uiDir)) cpSync(uiDir, join(appRoot, 'ui'), { recursive: true })

  const modules: string[] = []
  for (const site of bp.sites) {
    const mode = plan.sites[site.id]
    if (!mode) throw new Error(`materialize: plan has no mode for site ${site.id}`)
    const srcFile = join(appDir, 'sites', site.id, `${mode}.ts`)
    if (!existsSync(srcFile)) throw new Error(`materialize: missing site twin ${srcFile}`)
    const destFile = join(sourceDir, ...site.rootCause.file.split('/'))
    // Cosmetic import rewrite: `'../../src/` (from sites/<id>/) -> `'../` (from src/<subdir>/).
    const content = readFileSync(srcFile, 'utf8').replace(/(['"])\.\.\/\.\.\/src\//g, '$1../')
    mkdirSync(dirname(destFile), { recursive: true })
    writeFileSync(destFile, content)
    modules.push(site.rootCause.file)
  }

  // Domain semantics are app-visible (the server enforces them); site modes, personas, truth and
  // chain specs never are.
  const variant = {
    app,
    apiPrefix: plan.apiPrefix,
    routes: plan.routes,
    params: plan.params,
    idFormat: plan.idFormat,
    domain: plan.domain,
  }
  const variantPath = join(sourceDir, 'variant.json')
  writeFileSync(variantPath, `${JSON.stringify(variant, null, 2)}\n`)
  writeFileSync(join(sourceDir, 'modules.json'), `${JSON.stringify(modules, null, 2)}\n`)

  assertVariantClean(variantPath)
  assertNoLeakage(root)
  return {
    root,
    sourceDir,
    uiDir: join(appRoot, 'ui'),
    variantPath,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  }
}
