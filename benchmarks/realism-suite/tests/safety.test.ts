// Tree-wide containment guard for the realism suite: no process spawning, no dynamic
// code evaluation, and every socket bind goes through lib/safety.ts on 127.0.0.1:0.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { extname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..')
const SELF = join(ROOT, 'tests', 'safety.test.ts')
const SCANNED = new Set(['.ts', '.js', '.mjs'])

function walk(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'out') continue
    const path = join(dir, name)
    if (statSync(path).isDirectory()) out.push(...walk(path))
    else if (SCANNED.has(extname(path))) out.push(path)
  }
  return out
}

const files = walk(ROOT).filter((file) => file !== SELF)

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')
}

test('no forbidden runtime constructs in the realism suite', () => {
  const banned: Array<{ re: RegExp; label: string }> = [
    { re: /(?:from|require\s*\()\s*['"](?:node:)?child_process['"]/, label: 'child_process' },
    { re: /(?:from|require\s*\()\s*['"](?:node:)?vm['"]/, label: 'vm' },
    { re: /(?:^|[^.\w])eval\s*\(/, label: 'eval(' },
    { re: /\bnew\s+Function\s*\(/, label: 'new Function' },
  ]
  const hits: string[] = []
  for (const file of files) {
    const code = stripComments(readFileSync(file, 'utf8'))
    for (const rule of banned) if (rule.re.test(code)) hits.push(`${relative(ROOT, file)}: ${rule.label}`)
  }
  assert.deepEqual(hits, [], `forbidden constructs:\n${hits.join('\n')}`)
})

test('the only raw .listen() is the loopback helper', () => {
  const offenders: string[] = []
  for (const file of files) {
    const rel = relative(ROOT, file)
    const code = stripComments(readFileSync(file, 'utf8'))
    for (const match of code.matchAll(/\.listen\s*\(/g)) {
      if (rel === join('lib', 'safety.ts') || rel === 'lib/safety.ts') continue
      const line = code.slice(0, match.index).split('\n').length
      offenders.push(`${rel}:${line}`)
    }
  }
  assert.deepEqual(offenders, [], `direct listens must use listenLoopback:\n${offenders.join('\n')}`)
})

test('no wildcard or non-loopback bind literals', () => {
  const offenders: string[] = []
  for (const file of files) {
    const rel = relative(ROOT, file)
    if (rel === 'lib/safety.ts') continue
    const code = stripComments(readFileSync(file, 'utf8'))
    if (/0\.0\.0\.0|:::|host\s*:\s*true/.test(code)) offenders.push(rel)
  }
  assert.deepEqual(offenders, [])
})

test('all network origins in fixtures are loopback', () => {
  const offenders: string[] = []
  for (const file of files) {
    const rel = relative(ROOT, file)
    if (rel.startsWith('tests/')) continue
    const code = stripComments(readFileSync(file, 'utf8'))
    for (const match of code.matchAll(/https?:\/\/([a-z0-9.-]+)/gi)) {
      const host = match[1].toLowerCase()
      if (host === '127.0.0.1' || host === 'localhost' || host.endsWith('.invalid') || host.endsWith('.example')) continue
      // Intentional open-redirect target used only as an expected Location value.
      if (host === 'evil.example') continue
      offenders.push(`${rel}: ${match[0]}`)
    }
  }
  assert.deepEqual(offenders, [], `non-loopback URL literals:\n${offenders.join('\n')}`)
})
