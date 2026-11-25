// Tree-wide containment guard for the multi-hop suite. This file names the patterns it forbids and
// is excluded from its own scan; every other TypeScript file is checked.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  existsSync, mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { extname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { assertLocalLabAllowed, localLabAllowed } from '../lib/safety.ts'
import { generateDomainVariant, listSeeds, resolveSeed, seedSetFor, tenantSlugsPrefixOverlap } from '../lib/domain-variant.ts'
import { materialize, scanTreeForLeakage, assertNoLeakage } from '../lib/materialize.ts'
import { createEgress } from '../lib/egress.ts'
import { startPaygrid } from '../apps/paygrid/index.ts'

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..')
const SELF = join(ROOT, 'tests', 'safety.test.ts')
const SCANNED = new Set(['.ts', '.js', '.mjs', '.json'])

function walk(dir: string): string[] {
  if (!existsSync(dir)) return []
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'out') continue
    const path = join(dir, name)
    const stat = statSync(path)
    if (stat.isDirectory()) out.push(...walk(path))
    else if (SCANNED.has(extname(path))) out.push(path)
  }
  return out
}

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')
}

const files = walk(ROOT).filter((file) => file !== SELF)

test('no forbidden runtime constructs anywhere under multihop-saas', () => {
  const banned: Array<{ re: RegExp; label: string }> = [
    { re: /(?:from|require\s*\()\s*['"](?:node:)?child_process['"]/, label: 'child_process' },
    { re: /(?:^|[^.\w])eval\s*\(/, label: 'eval(' },
    { re: /\bnew\s+Function\s*\(/, label: 'new Function' },
    { re: /(?:from|require\s*\()\s*['"](?:node:)?vm['"]/, label: 'vm' },
    { re: /(?:from|require\s*\()\s*['"](?:node:)?worker_threads['"]/, label: 'worker_threads' },
  ]
  const hits: string[] = []
  for (const file of files) {
    if (!file.endsWith('.ts')) continue
    const code = stripComments(readFileSync(file, 'utf8'))
    for (const entry of banned) {
      if (entry.re.test(code)) hits.push(`${relative(ROOT, file)}: ${entry.label}`)
    }
  }
  assert.deepEqual(hits, [], `forbidden constructs found:\n${hits.join('\n')}`)
})

test('only lib/safety.ts binds a socket, and only to loopback port 0', () => {
  const offenders: string[] = []
  for (const file of files) {
    if (!file.endsWith('.ts')) continue
    const rel = relative(ROOT, file)
    const source = readFileSync(file, 'utf8')
    for (const match of source.matchAll(/\.listen\s*\(/g)) {
      const slice = source.slice(match.index, match.index + 120)
      if (rel === 'lib/safety.ts' && slice.includes('LOOPBACK')) continue
      offenders.push(`${rel}: ${slice.split('\n')[0]}`)
    }
  }
  assert.deepEqual(offenders, [], `raw .listen() calls must go through listenLoopback:\n${offenders.join('\n')}`)
})

test('no wildcard bind address and no non-loopback URL literal', () => {
  const problems: string[] = []
  for (const file of files) {
    if (!file.endsWith('.ts')) continue
    const code = stripComments(readFileSync(file, 'utf8'))
    if (code.includes('0.0.0.0')) problems.push(`${relative(ROOT, file)}: wildcard bind literal`)
    for (const found of code.matchAll(/['"](https?:\/\/[^'"]+)['"]/g)) {
      const url = found[1]!
      if (!url.includes('127.0.0.1') && !url.includes('.invalid') && !url.includes('.example') &&
        !url.includes('localhost')) {
        problems.push(`${relative(ROOT, file)}: external URL literal ${url}`)
      }
    }
  }
  assert.deepEqual(problems, [], `unsafe bind/egress literals:\n${problems.join('\n')}`)
})

test('zero npm dependencies, ESM-only, explicit .ts relative imports', () => {
  const problems: string[] = []
  if (existsSync(join(ROOT, 'package.json'))) problems.push('nested package.json under multihop-saas')
  const staticRe = /\bfrom\s+['"]([^'"]+)['"]/g
  const dynamicRe = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g
  for (const file of files) {
    if (!file.endsWith('.ts')) continue
    const rel = relative(ROOT, file)
    const code = stripComments(readFileSync(file, 'utf8'))
    for (const re of [staticRe, dynamicRe]) {
      re.lastIndex = 0
      let match: RegExpExecArray | null
      while ((match = re.exec(code)) !== null) {
        const spec = match[1]!
        if (spec.startsWith('node:')) continue
        if (spec.startsWith('.')) {
          if (!spec.endsWith('.ts') && !spec.endsWith('.json')) problems.push(`${rel}: import must end in .ts (${spec})`)
          continue
        }
        problems.push(`${rel}: non-node bare import '${spec}'`)
      }
    }
    if (/\brequire\s*\(/.test(code)) problems.push(`${rel}: require() is not allowed`)
  }
  assert.deepEqual(problems, [], `dependency/import violations:\n${problems.join('\n')}`)
})

test('synthetic-only secret material', () => {
  const problems: string[] = []
  for (const file of files) {
    if (!file.endsWith('.ts')) continue
    const rel = relative(ROOT, file)
    const code = stripComments(readFileSync(file, 'utf8'))
    if (/FLAG\{/.test(code)) problems.push(`FLAG marker: ${rel}`)
    if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(code)) problems.push(`private key: ${rel}`)
    if (/\bsk-[A-Za-z0-9]{20,}/.test(code)) problems.push(`provider-style key: ${rel}`)
    if (/\bAKIA[0-9A-Z]{16}\b/.test(code)) problems.push(`cloud key id: ${rel}`)
  }
  const plan = generateDomainVariant('paygrid', 42)
  for (const secret of Object.values(plan.secrets)) assert.match(secret, /^mh_fake_/)
  assert.match(plan.economics.treasuryCanary, /^mh_fake_canary_/)
  for (const persona of Object.values(plan.personas)) assert.match(persona.password, /^mh_fake_pw_/)
  assert.deepEqual(problems, [], `secret/leak markers:\n${problems.join('\n')}`)
})

test('local-lab gate refuses to start any server without KOVO_ALLOW_LOCAL_LAB=1', async () => {
  const previous = process.env.KOVO_ALLOW_LOCAL_LAB
  delete process.env.KOVO_ALLOW_LOCAL_LAB
  try {
    assert.equal(localLabAllowed(), false)
    assert.throws(() => assertLocalLabAllowed(), /KOVO_ALLOW_LOCAL_LAB=1/)
    await assert.rejects(
      () => startPaygrid({ seed: 1, mode: 'vulnerable', asyncLatencyMs: 1 }),
      /KOVO_ALLOW_LOCAL_LAB=1/,
    )
  } finally {
    if (previous === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = previous
  }
})

test('every entrypoint calls the gate; server start does too', () => {
  for (const rel of ['run.ts', 'lib/safety.ts', 'apps/paygrid/index.ts', 'apps/paygrid/src/server.ts']) {
    assert.match(readFileSync(join(ROOT, rel), 'utf8'), /assertLocalLabAllowed\s*\(/, `${rel} must call the gate`)
  }
})

test('materialized white-box tree is leakage-free (content and paths)', () => {
  const plan = generateDomainVariant('paygrid', 42)
  const materialized = materialize({ app: 'paygrid', plan })
  try {
    assert.deepEqual(scanTreeForLeakage(materialized.root), [])
    assert.doesNotThrow(() => assertNoLeakage(materialized.root))
    const snapshot = readdirSync(materialized.sourceDir)
    assert.ok(snapshot.includes('server.ts'))
    assert.ok(!snapshot.some((name) => /truth|solver|decoy|oracle/i.test(name)))
  } finally {
    materialized.cleanup()
  }

  const scratch = mkdtempSync(join(tmpdir(), 'multihop-leak-'))
  try {
    const source = join(scratch, 'apps', 'paygrid', 'src')
    mkdirSync(source, { recursive: true })
    writeFileSync(join(source, 'server.ts'), 'export const ready = true\n')
    assert.deepEqual(scanTreeForLeakage(scratch), [])
    writeFileSync(join(source, 'server.ts'), '// legacy hardened branch\n')
    assert.ok(scanTreeForLeakage(scratch).some((problem) => problem.includes('leaky content')))
    writeFileSync(join(source, 'server.ts'), 'export {}\n')
    mkdirSync(join(scratch, 'apps', 'paygrid', 'truth'), { recursive: true })
    writeFileSync(join(scratch, 'apps', 'paygrid', 'truth', 'blueprint.ts'), 'export {}\n')
    assert.ok(scanTreeForLeakage(scratch).some((problem) => problem.includes('leaky path segment')))
    assert.throws(() => assertNoLeakage(scratch), /assertNoLeakage failed/)
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
})

test('egress refuses unregistered targets, external hosts and non-loopback URLs', async () => {
  const egress = createEgress()
  await assert.rejects(() => egress.fetch('api', '/health'), /egress blocked/)
  const attempts = egress.attempts()
  assert.equal(attempts.length, 1)
  assert.equal(attempts[0]!.allowed, false)
  assert.equal(attempts[0]!.reason, 'target_blocked')
  assert.throws(() => egress.register({ name: 'outside', origin: 'http://10.0.0.1:80', internal: false }), /non-loopback/)
})

test('seed sets: dev 1..9999, salted held-out >= 1_000_000 via KOVO_RB_HELDOUT_SALT', () => {
  assert.deepEqual(listSeeds('dev', 3), [1, 2, 3])
  assert.equal(seedSetFor(9999), 'dev')
  assert.equal(seedSetFor(1_000_000), 'held-out')
  const previous = process.env.KOVO_RB_HELDOUT_SALT
  delete process.env.KOVO_RB_HELDOUT_SALT
  try {
    assert.throws(() => listSeeds('held-out', 1), /KOVO_RB_HELDOUT_SALT/)
  } finally {
    if (previous === undefined) delete process.env.KOVO_RB_HELDOUT_SALT
    else process.env.KOVO_RB_HELDOUT_SALT = previous
  }
  process.env.KOVO_RB_HELDOUT_SALT = 'unit-test-held-out-salt'
  const held = listSeeds('held-out', 3)
  assert.equal(held.length, 3)
  assert.ok(held.every((seed) => seed >= 1_000_000))
  assert.equal(new Set(held).size, held.length)
  const resolved = resolveSeed(held[0]!, 'unit-test-held-out-salt')
  assert.equal(resolved.seedSet, 'held-out')
})

test('seven personas across three tenants with prefix-overlapping slugs', () => {
  const plan = generateDomainVariant('paygrid', 7)
  assert.equal(Object.keys(plan.personas).length, 7)
  assert.equal(Object.keys(plan.tenants).length, 3)
  assert.ok(tenantSlugsPrefixOverlap(plan.tenants.a.slug, plan.tenants.b.slug))
  assert.ok(tenantSlugsPrefixOverlap(plan.tenants.b.slug, plan.tenants.c.slug))
  assert.equal(plan.personas.admin_bot.bot, true)
  assert.deepEqual(plan.personas.dual_member.rolesByTenant, { org_a: 'admin', org_b: 'viewer' })
})
