// Materialize a per-seed app tree for white-box mounting. Copies generic lib + app src/ui, then
// lays down the chosen (vulnerable|hardened) site file at its neutral rootCause path, and writes
// variant.json / modules.json. Finally asserts no white-box leakage of truth into the app tree.
import { randomBytes } from 'node:crypto'
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, sep } from 'node:path'
import { tmpdir } from 'node:os'
import type { AppBlueprint, VariantPlan } from '../lib/types.ts'

const BANNED = /vulnerab|hardened|decoy|oracle|solver|CWE-|ground.?truth/i

export interface MaterializeInput {
  bp: AppBlueprint
  plan: VariantPlan
  appDir: string // apps/<app> source dir in the repo
  libDir: string // generic lib/ dir in the repo
  uiSubdir?: string // defaults to 'ui'
  outRoot?: string // defaults to os.tmpdir()
}

export interface MaterializeResult {
  root: string
  sourceDir: string
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

/** Fail if any app-tree file leaks truth: banned content, or a `sites/`/`truth/` path. */
export function assertNoLeakage(root: string): void {
  const appsDir = join(root, 'apps')
  const problems: string[] = []
  walk(appsDir, (file) => {
    const parts = file.split(sep)
    if (parts.includes('sites') || parts.includes('truth')) problems.push(`leaky path: ${file}`)
    if (BANNED.test(readFileSync(file, 'utf8'))) problems.push(`leaky content in: ${file}`)
  })
  if (problems.length) throw new Error(`assertNoLeakage failed under ${appsDir}:\n  - ${problems.join('\n  - ')}`)
}

export function materialize(input: MaterializeInput): MaterializeResult {
  const { bp, plan, appDir, libDir } = input
  const app = plan.app
  const root = join(input.outRoot ?? tmpdir(), 'realistic-bench', `${app}-${plan.seed}-${randomBytes(4).toString('hex')}`)
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
    const destFile = join(sourceDir, ...site.rootCause.file.split('/'))
    // Cosmetic import rewrite: `'../../src/` (from sites/<id>/) -> `'../` (from src/<subdir>/).
    const content = readFileSync(srcFile, 'utf8').replace(/(['"])\.\.\/\.\.\/src\//g, '$1../')
    mkdirSync(dirname(destFile), { recursive: true })
    writeFileSync(destFile, content)
    modules.push(site.rootCause.file)
  }

  const variant = { app, apiPrefix: plan.apiPrefix, routes: plan.routes, params: plan.params, idFormat: plan.idFormat }
  const variantPath = join(sourceDir, 'variant.json')
  writeFileSync(variantPath, `${JSON.stringify(variant, null, 2)}\n`)
  writeFileSync(join(sourceDir, 'modules.json'), `${JSON.stringify(modules, null, 2)}\n`)

  assertNoLeakage(root)
  return { root, sourceDir, variantPath, cleanup: () => rmSync(root, { recursive: true, force: true }) }
}
