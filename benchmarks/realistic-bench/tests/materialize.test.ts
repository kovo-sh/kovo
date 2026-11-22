import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { generateVariant } from '../generator/variant.ts'
import { buildGroundTruth } from '../generator/groundtruth.ts'
import { materialize, assertNoLeakage } from '../generator/materialize.ts'
import { miniBlueprint } from './fixtures/mini-blueprint.ts'

const TESTS_DIR = import.meta.dirname
const APP_DIR = join(TESTS_DIR, 'fixtures', 'mini-app')
const LIB_DIR = join(TESTS_DIR, '..', 'lib')

const rewrite = (s: string): string => s.replace(/(['"])\.\.\/\.\.\/src\//g, '$1../')

test('materialize lays down the chosen site file and blocks leakage', async () => {
  const plan = generateVariant(miniBlueprint, 7)
  const gt = buildGroundTruth(miniBlueprint, plan)
  assert.equal(gt.vulns.length + gt.decoys.length, 2)

  const res = materialize({ bp: miniBlueprint, plan, appDir: APP_DIR, libDir: LIB_DIR })
  try {
    // rootCause file exists and equals the chosen (rewritten) variant.
    const mode = plan.sites['demo-site']!
    const thingPath = join(res.sourceDir, 'area', 'thing.ts')
    assert.ok(existsSync(thingPath), 'rootCause file materialized')
    const expected = rewrite(readFileSync(join(APP_DIR, 'sites', 'demo-site', `${mode}.ts`), 'utf8'))
    assert.equal(readFileSync(thingPath, 'utf8'), expected)
    assert.ok(existsSync(join(res.root, 'lib', 'prng.ts')), 'lib copied')
    assert.ok(existsSync(join(res.root, 'apps', 'mini-app', 'ui', 'index.html')), 'ui copied')

    // variant.json has no site modes or truth; modules.json lists both sites.
    const variant = JSON.parse(readFileSync(res.variantPath, 'utf8'))
    assert.deepEqual(Object.keys(variant).sort(), ['apiPrefix', 'app', 'idFormat', 'params', 'routes'])
    assert.ok(!('sites' in variant) && !('personas' in variant))
    const modules = JSON.parse(readFileSync(join(res.sourceDir, 'modules.json'), 'utf8'))
    assert.deepEqual([...modules].sort(), ['area/thing.ts', 'area/widget.ts'])

    // Imports in the copied site file resolve at runtime.
    const mod = await import(pathToFileURL(thingPath).href)
    assert.equal(typeof mod.loadInvoice, 'function')
    assert.equal(typeof mod.register, 'function')

    // No leakage in the clean tree.
    assert.doesNotThrow(() => assertNoLeakage(res.root))

    // Planting a banned word into an app-tree file makes the scan fail.
    const serverPath = join(res.sourceDir, 'server.ts')
    writeFileSync(serverPath, `${readFileSync(serverPath, 'utf8')}\n// hardened\n`)
    assert.throws(() => assertNoLeakage(res.root), /assertNoLeakage failed/)
  } finally {
    res.cleanup()
    assert.ok(!existsSync(res.root), 'cleanup removed the tree')
  }
})
