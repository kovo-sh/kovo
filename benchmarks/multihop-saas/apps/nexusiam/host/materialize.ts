// White-box materialization for nexusiam: copy only the service source plus the runtime helpers,
// then prove the snapshot carries no host-side chain markers.
import { randomBytes } from 'node:crypto'
import { cpSync, existsSync, mkdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { assertNoLeakage } from '../../../lib/materialize.ts'
import type { NexusPlan, ServiceName } from '../src/shared.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const APP_DIR = join(HERE, '..')
const APP_SRC = join(APP_DIR, 'src')
const BENCH_ROOT = join(APP_DIR, '..', '..')
const LIB_DIR = join(BENCH_ROOT, 'lib')

const COPIED_RUNTIME = ['safety.ts', 'egress.ts', 'vfs.ts'] as const
const SERVICES: ServiceName[] = ['cdn', 'app', 'api', 'idp', 'docs-worker']

export interface MaterializeNexusiamResult {
  root: string
  sourceDir: string
  cleanup(): void
}

export function materializeNexusiam(plan: NexusPlan): MaterializeNexusiamResult {
  if (!existsSync(APP_SRC) || !statSync(APP_SRC).isDirectory()) {
    throw new Error(`materialize: no src/ under ${APP_DIR}`)
  }
  const root = join(tmpdir(), 'multihop-saas', `nexusiam-${plan.seed}-${randomBytes(4).toString('hex')}`)
  rmSync(root, { recursive: true, force: true })
  const sourceDir = join(root, 'apps', 'nexusiam', 'src')
  mkdirSync(dirname(sourceDir), { recursive: true })
  cpSync(APP_SRC, sourceDir, { recursive: true })

  const libDir = join(root, 'lib')
  mkdirSync(libDir, { recursive: true })
  for (const file of COPIED_RUNTIME) cpSync(join(LIB_DIR, file), join(libDir, file))

  const descriptor = {
    seed: plan.seed,
    seedSet: plan.seedSet,
    routePrefix: plan.routePrefix,
    tenants: plan.tenants,
    services: SERVICES,
  }
  writeFileSync(join(root, 'variant.json'), `${JSON.stringify(descriptor, null, 2)}\n`)
  writeFileSync(join(root, 'README.md'), '# nexusiam workspace snapshot\n')

  assertNoLeakage(root)
  return {
    root,
    sourceDir,
    cleanup() {
      rmSync(root, { recursive: true, force: true })
    },
  }
}
