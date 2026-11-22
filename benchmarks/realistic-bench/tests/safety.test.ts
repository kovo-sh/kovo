// Tree-wide containment guard: fail if any benchmark file uses a forbidden runtime construct or
// binds a non-loopback socket. This is a belt-and-suspenders check over every .ts/.js/.mjs/.html
// file under realistic-bench (except this file, which necessarily names the patterns it forbids).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, extname, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..')
const SELF = join(ROOT, 'tests', 'safety.test.ts')
const SCANNED = new Set(['.ts', '.js', '.mjs', '.html'])

function walk(dir: string): string[] {
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

const files = walk(ROOT).filter((f) => f !== SELF)

// Files legitimately allowed to touch the real filesystem (build tooling + the one jailed static reader).
const FS_ALLOWED = [
  'lib/http-static.ts', // jailed UI static server (prefix-checked against realpath)
  'generator/materialize.ts', // build-time temp-tree materialization
  'grader/schema.ts', // writes ground-truth.schema.json (tooling)
  'run.ts',
  'guardian-adapter.ts', // tooling: reads the materialized variant.json (routes only) + realpath guard
  'benchmark-realistic.ts', // tooling: writes scorecard/findings artifacts under --out-*
]

test('no forbidden runtime constructs anywhere under realistic-bench', () => {
  // Match real usage (imports / dynamic requires / calls), not assert-absence regexes in tests.
  const banned: Array<{ re: RegExp; label: string }> = [
    { re: /(?:from|require\s*\()\s*['"](?:node:)?child_process['"]/, label: 'child_process' },
    { re: /(?:^|[^.\w])eval\s*\(/, label: 'eval(' },
    { re: /\bnew\s+Function\s*\(/, label: 'new Function' },
    { re: /(?:from|require\s*\()\s*['"](?:node:)?vm['"]/, label: 'vm' },
  ]
  const hits: string[] = []
  for (const f of files) {
    if (f.endsWith('.html')) continue
    const src = readFileSync(f, 'utf8')
    // strip line + block comments so an explanatory comment does not trip the guard
    const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')
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
    // Flag raw binds that pass an explicit arg (port/host). The framework's own zero-arg
    // `app.listen()` routes through listenLoopback and is safe.
    for (const m of src.matchAll(/\.listen\s*\(\s*[^)]/g)) {
      const slice = src.slice(m.index, m.index + 120)
      if (rel === 'lib/safety.ts' && slice.includes('LOOPBACK')) continue
      offenders.push(`${rel}: ${slice.split('\n')[0]}`)
    }
  }
  assert.deepEqual(offenders, [], `raw .listen() calls must go through listenLoopback:\n${offenders.join('\n')}`)
})

test('node:fs is confined to the allowlisted tooling/static files', () => {
  const offenders: string[] = []
  for (const f of files) {
    if (f.endsWith('.html') || relative(ROOT, f).startsWith('tests/')) continue
    const rel = relative(ROOT, f)
    const src = readFileSync(f, 'utf8')
    const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')
    if (/from\s+['"]node:fs['"]/.test(code) && !FS_ALLOWED.includes(rel)) offenders.push(rel)
  }
  assert.deepEqual(offenders, [], `unexpected node:fs import (lab runtime must use lib/vfs):\n${offenders.join('\n')}`)
})
