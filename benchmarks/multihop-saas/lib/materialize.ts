// White-box materialization: copy the app's service source (plus the small runtime helpers it
// imports) into a temporary tree, write a neutral variant descriptor, and prove the copied tree
// carries no host-side chain markers.
import { randomBytes } from 'node:crypto'
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, extname, join, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { AppName, DomainVariant } from './types.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
export const BENCH_ROOT = join(HERE, '..')
export const APPS_ROOT = join(BENCH_ROOT, 'apps')

const COPIED_RUNTIME = ['safety.ts', 'egress.ts', 'vfs.ts'] as const
const SCANNED = new Set(['.ts', '.js', '.mjs', '.json', '.md', '.html'])
const BANNED_CONTENT =
  /vulnerab\w*|\bhardened\b|\bdecoy\w*\b|\boracle\w*\b|\bsolver\w*\b|CWE-\d+|ground.?truth|PG-[CD]\d/i
const BANNED_PATH_SEGMENTS = new Set(['truth', 'solvers', 'solver', 'decoy', 'oracle', 'chains'])

export interface MaterializeInput {
  app: AppName
  plan: DomainVariant
  outRoot?: string
}

export interface MaterializeResult {
  root: string
  sourceDir: string
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

/** Every leakage problem under `root`: forbidden path segments or content markers. */
export function scanTreeForLeakage(root: string): string[] {
  const problems: string[] = []
  walk(root, (file) => {
    if (!SCANNED.has(extname(file))) return
    const relativeParts = file.slice(root.length + 1).split(sep)
    const badSegment = relativeParts.find((part) => BANNED_PATH_SEGMENTS.has(part.replace(extname(part), '')))
    if (badSegment) problems.push(`leaky path segment '${badSegment}': ${file}`)
    const content = readFileSync(file, 'utf8')
    const match = BANNED_CONTENT.exec(content)
    if (match) problems.push(`leaky content '${match[0]}' in: ${file}`)
  })
  return problems
}

export function assertNoLeakage(root: string): void {
  const problems = scanTreeForLeakage(root)
  if (problems.length) throw new Error(`assertNoLeakage failed under ${root}:\n  - ${problems.join('\n  - ')}`)
}

export function materialize(input: MaterializeInput): MaterializeResult {
  const appDir = join(APPS_ROOT, input.app)
  const appSrc = join(appDir, 'src')
  if (!existsSync(appSrc) || !statSync(appSrc).isDirectory()) {
    throw new Error(`materialize: no src/ under ${appDir}`)
  }
  const root = join(
    input.outRoot ?? tmpdir(),
    'multihop-saas',
    `${input.app}-${input.plan.seed}-${randomBytes(4).toString('hex')}`,
  )
  rmSync(root, { recursive: true, force: true })
  const sourceDir = join(root, 'apps', input.app, 'src')
  mkdirSync(dirname(sourceDir), { recursive: true })
  cpSync(appSrc, sourceDir, { recursive: true })

  const libDir = join(root, 'lib')
  mkdirSync(libDir, { recursive: true })
  for (const file of COPIED_RUNTIME) cpSync(join(HERE, file), join(libDir, file))

  const descriptor = {
    seed: input.plan.seed,
    seedSet: input.plan.seedSet,
    routePrefix: input.plan.routePrefix,
    tenants: input.plan.tenants,
    services: ['edge', 'api', 'worker', 'idp', 'vault.internal'],
  }
  writeFileSync(join(root, 'variant.json'), `${JSON.stringify(descriptor, null, 2)}\n`)
  writeFileSync(join(root, 'README.md'), '# paygrid lab source snapshot\n')

  assertNoLeakage(root)
  return {
    root,
    sourceDir,
    cleanup() {
      rmSync(root, { recursive: true, force: true })
    },
  }
}
