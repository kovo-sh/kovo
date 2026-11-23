// Tree-wide containment guard for reason-bench: fail if any benchmark file uses a forbidden runtime
// construct, binds a non-loopback socket, reaches the network outside lib/egress.ts, touches the real
// filesystem outside the allowlisted tooling/static files, imports a non-node dependency, or writes a
// materialized tree that leaks truth/mode markers. This file necessarily names the patterns it forbids
// and is excluded from its own scan.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, extname, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { localLabAllowed, assertLocalLabAllowed } from '../lib/safety.ts'
import { createEgress, startInternalService } from '../lib/egress.ts'
import { createOracle } from '../lib/oracle.ts'
import { runWithCtx, noteInput } from '../lib/oracle.ts'
import { createVfs } from '../lib/vfs.ts'
import { createCanaryRegistry } from '../lib/canary.ts'
import { scanTreeForLeakage, assertNoLeakage } from '../generator/materialize.ts'
import { discoverAppNames } from '../generator/variant.ts'
import { listSeeds } from '../generator/seeds.ts'

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..')
const SELF = join(ROOT, 'tests', 'safety.test.ts')
const SCANNED = new Set(['.ts', '.js', '.mjs', '.html'])

function walk(dir: string): string[] {
  if (!statExists(dir)) return []
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'out') continue
    const p = join(dir, name)
    const st = statSync(p)
    if (st.isDirectory()) out.push(...walk(p))
    else if (SCANNED.has(extname(p))) out.push(p)
  }
  return out
}

function statExists(p: string): boolean {
  try { statSync(p); return true } catch { return false }
}

function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')
}

const files = walk(ROOT).filter((f) => f !== SELF)

test('no forbidden runtime constructs anywhere under reason-bench', () => {
  const banned: Array<{ re: RegExp; label: string }> = [
    { re: /(?:from|require\s*\()\s*['"](?:node:)?child_process['"]/, label: 'child_process' },
    { re: /(?:^|[^.\w])eval\s*\(/, label: 'eval(' },
    { re: /\bnew\s+Function\s*\(/, label: 'new Function' },
    { re: /(?:from|require\s*\()\s*['"](?:node:)?vm['"]/, label: 'vm' },
  ]
  const hits: string[] = []
  for (const f of files) {
    if (f.endsWith('.html')) continue
    const code = stripComments(readFileSync(f, 'utf8'))
    for (const b of banned) if (b.re.test(code)) hits.push(`${relative(ROOT, f)}: ${b.label}`)
  }
  assert.deepEqual(hits, [], `forbidden constructs found:\n${hits.join('\n')}`)
})

test('only safety.ts binds a socket, and only to 127.0.0.1', () => {
  const offenders: string[] = []
  for (const f of files) {
    if (f.endsWith('.html')) continue
    const rel = relative(ROOT, f)
    const src = readFileSync(f, 'utf8')
    for (const m of src.matchAll(/\.listen\s*\(\s*[^)]/g)) {
      const slice = src.slice(m.index, m.index + 120)
      if (rel === 'lib/safety.ts' && slice.includes('LOOPBACK')) continue
      offenders.push(`${rel}: ${slice.split('\n')[0]}`)
    }
  }
  assert.deepEqual(offenders, [], `raw .listen() calls must go through listenLoopback:\n${offenders.join('\n')}`)
})

test('outbound HTTP only via lib/egress.ts', () => {
  const offenders: string[] = []
  for (const f of files) {
    if (f.endsWith('.html')) continue
    const rel = relative(ROOT, f)
    if (rel === 'lib/egress.ts' || rel === 'lib/http.ts' || rel === 'lib/safety.ts') continue
    const code = stripComments(readFileSync(f, 'utf8'))
    if (/\bhttp\.request\s*\(|\bhttps\.request\s*\(|\bfetch\s*\(\s*['"]https?:/.test(code)) offenders.push(rel)
  }
  assert.deepEqual(offenders, [], `network calls must flow through lib/egress.ts:\n${offenders.join('\n')}`)
})

test('node:fs is confined to allowlisted tooling/static files', () => {
  const FS_ALLOWED = [
    'lib/http-static.ts', // jailed UI static server (prefix-checked against realpath)
    'generator/materialize.ts', // build-time temp-tree materialization + leakage scan
    'generator/variant.ts', // build-time dynamic site/app discovery
    'grader/schema.ts', // writes ground-truth.schema.json (tooling)
    'run.ts',
  ]
  const offenders: string[] = []
  for (const f of files) {
    if (f.endsWith('.html') || relative(ROOT, f).startsWith('tests/')) continue
    const rel = relative(ROOT, f)
    const code = stripComments(readFileSync(f, 'utf8'))
    // Host-side app wiring (index.ts, truth/) drives materialization/discovery and is never
    // copied into the materialized tree; only apps/*/src and apps/*/ui are leakage-scanned.
    const hostSide = /^apps\/[^/]+\/(index\.ts|truth\/)/.test(rel)
    if (/from\s+['"]node:fs['"]/.test(code) && !FS_ALLOWED.includes(rel) && !hostSide) offenders.push(rel)
  }
  assert.deepEqual(offenders, [], `unexpected node:fs import (lab runtime must use lib/vfs):\n${offenders.join('\n')}`)
})

test('zero npm dependencies and explicit .ts relative imports', () => {
  const problems: string[] = []
  const staticRe = /\bfrom\s+['"]([^'"]+)['"]/g
  const dynamicRe = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g
  for (const f of files) {
    if (!f.endsWith('.ts')) continue
    const rel = relative(ROOT, f)
    const code = stripComments(readFileSync(f, 'utf8'))
    for (const re of [staticRe, dynamicRe]) {
      re.lastIndex = 0
      let m: RegExpExecArray | null
      while ((m = re.exec(code)) !== null) {
        const spec = m[1]!
        if (spec.startsWith('node:')) continue
        if (spec.startsWith('.')) {
          if (!spec.endsWith('.ts') && !spec.endsWith('.json')) problems.push(`${rel}: relative import must end in .ts (${spec})`)
          continue
        }
        problems.push(`${rel}: non-node bare import '${spec}'`)
      }
    }
    if (/\brequire\s*\(/.test(code)) problems.push(`${rel}: require() is not allowed (ESM + native TS)`)
  }
  assert.deepEqual(problems, [], `dependency/import violations:\n${problems.join('\n')}`)
})

test('no materialized package.json, no real-looking secrets or FLAG markers', () => {
  const problems: string[] = []
  if (statExists(join(ROOT, 'package.json'))) problems.push('nested package.json under reason-bench')
  for (const f of files) {
    const rel = relative(ROOT, f)
    if (rel.endsWith('.html')) continue
    const code = stripComments(readFileSync(f, 'utf8'))
    if (/FLAG\{/.test(code)) problems.push(`FLAG marker: ${rel}`)
    if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(code)) problems.push(`private key: ${rel}`)
    if (/\bsk-[A-Za-z0-9]{20,}/.test(code)) problems.push(`provider-style key: ${rel}`)
  }
  const canaries = createCanaryRegistry('reason-bench-test-salt')
  assert.match(canaries.tenantToken('acme', 'invoice'), /^rbc_acme_[0-9a-f]{12}$/)
  assert.match(canaries.secretToken('acme', 'api-key'), /^rbs_acme_[0-9a-f]{12}$/)
  assert.deepEqual(problems, [], `secret/leak markers:\n${problems.join('\n')}`)
})

test('every entrypoint calls the local-lab gate', () => {
  for (const rel of ['run.ts', 'lib/http.ts', 'lib/egress.ts']) {
    assert.match(readFileSync(join(ROOT, rel), 'utf8'), /assertLocalLabAllowed\s*\(/, `${rel} must call assertLocalLabAllowed()`)
  }
})

test('local-lab gate refuses to start without GUARDIAN_ALLOW_LOCAL_LAB=1', () => {
  const prev = process.env.GUARDIAN_ALLOW_LOCAL_LAB
  delete process.env.GUARDIAN_ALLOW_LOCAL_LAB
  try {
    assert.equal(localLabAllowed(), false)
    assert.throws(() => assertLocalLabAllowed(), /GUARDIAN_ALLOW_LOCAL_LAB=1/)
  } finally {
    if (prev === undefined) delete process.env.GUARDIAN_ALLOW_LOCAL_LAB
    else process.env.GUARDIAN_ALLOW_LOCAL_LAB = prev
  }
  process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'
  assert.doesNotThrow(() => assertLocalLabAllowed())
})

test('egress allowlist permits only registered loopback ports and records blocks', async () => {
  const svc = await startInternalService({
    name: 'internal-meta',
    internal: true,
    handler: (_req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('ok') },
  })
  const oracle = createOracle({ app: 'ledgerflow' })
  try {
    const egress = createEgress({
      oracle,
      internalServices: [{ name: 'internal-meta', port: svc.port, internal: true }],
    })
    const allowed = await egress.fetch(`http://127.0.0.1:${svc.port}/meta`)
    assert.equal(allowed.status, 200)
    assert.equal(allowed.body, 'ok')

    await assert.rejects(() => egress.fetch('http://127.0.0.1:1/forbidden'), /egress blocked/)
    await assert.rejects(() => egress.fetch('http://8.8.8.8/forbidden'), /egress blocked/)
    const blocked = oracle.egress().filter((e) => !e.allowed)
    assert.ok(blocked.length >= 2)
    assert.ok(blocked.some((e) => e.reason.startsWith('port_blocked')))
    assert.ok(blocked.some((e) => e.reason.startsWith('host_blocked')))

    const url = `http://127.0.0.1:${svc.port}/internal`
    const ctx = {
      routeKey: 'meta.fetch', method: 'POST', path: '/fetch', actor: 'member_a' as const,
      tenant: 'acme', sessionId: null, inputs: [] as string[], inputSet: new Set<string>(), startedAt: 0,
    }
    await runWithCtx(ctx, async () => {
      noteInput(url)
      await egress.fetch(url)
    })
    assert.ok(oracle.events().some((e) => e.kind === 'ssrf_internal_fetch'))
  } finally {
    await svc.stop()
  }
})

test('VFS readWithin jails paths and records an escape without touching the real FS', () => {
  const oracle = createOracle({ app: 'forgecloud' })
  const vfs = createVfs(oracle, {
    '/exports/acme/report.txt': 'owner',
    '/exports/acme-corp/audit.json': 'sibling-secret',
  })
  assert.equal(vfs.readWithin('/exports/acme', 'report.txt'), 'owner')
  assert.equal(vfs.readWithin('/exports/acme', '../acme-corp/audit.json'), 'sibling-secret')
  assert.ok(oracle.events().some((e) => e.kind === 'path_escape'))
})

test('materialized app trees are leakage-scanned (content + truth/solver paths)', () => {
  const root = mkdtempSync(join(tmpdir(), 'reason-bench-leak-'))
  try {
    const src = join(root, 'apps', 'ledgerflow', 'src')
    mkdirSync(src, { recursive: true })
    const clean = join(src, 'server.ts')
    writeFileSync(clean, 'export function startServer(): void {}\n')
    assert.deepEqual(scanTreeForLeakage(root), [])
    assert.doesNotThrow(() => assertNoLeakage(root))

    writeFileSync(clean, '// this is the hardened twin\n')
    assert.ok(scanTreeForLeakage(root).some((p) => p.includes('leaky content')))

    writeFileSync(clean, 'export const ready = true\n')
    mkdirSync(join(root, 'apps', 'ledgerflow', 'truth'), { recursive: true })
    writeFileSync(join(root, 'apps', 'ledgerflow', 'truth', 'blueprint.ts'), 'export {}\n')
    assert.ok(scanTreeForLeakage(root).some((p) => p.includes('leaky path')))
    assert.throws(() => assertNoLeakage(root), /assertNoLeakage failed/)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('apps are discovered dynamically under apps/ (and may be absent during M0)', () => {
  const appsRoot = join(ROOT, 'apps')
  const names = discoverAppNames(appsRoot)
  assert.ok(Array.isArray(names))
  for (const name of names) assert.ok(statExists(join(appsRoot, name, 'index.ts')))
})

test('seed sets: dev is reproducible; held-out requires a salt', () => {
  assert.deepEqual(listSeeds('dev', 3), [1, 2, 3])
  const prev = process.env.GUARDIAN_RB_HELDOUT_SALT
  delete process.env.GUARDIAN_RB_HELDOUT_SALT
  try {
    assert.throws(() => listSeeds('held-out', 1), /GUARDIAN_RB_HELDOUT_SALT/)
  } finally {
    if (prev === undefined) delete process.env.GUARDIAN_RB_HELDOUT_SALT
    else process.env.GUARDIAN_RB_HELDOUT_SALT = prev
  }
  process.env.GUARDIAN_RB_HELDOUT_SALT = 'unit-test-held-out-salt'
  const held = listSeeds('held-out', 3)
  assert.equal(held.length, 3)
  assert.ok(held.every((n) => n >= 1_000_000))
  assert.equal(new Set(held).size, held.length)
})
