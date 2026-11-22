import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createOracle, runWithCtx } from '../lib/oracle.ts'
import type { RequestCtx } from '../lib/oracle.ts'
import { createVfs, defaultSystemFiles } from '../lib/vfs.ts'

function ctx(): RequestCtx {
  return {
    routeKey: 'r.download',
    method: 'GET',
    path: '/download',
    actor: 'persona_a',
    tenant: 't1',
    sessionId: 's1',
    inputs: [],
    inputSet: new Set(),
    startedAt: Date.now(),
  }
}

const JAIL = '/app/exports'

function mkVfs(oracle: ReturnType<typeof createOracle>) {
  return createVfs(oracle, {
    ...defaultSystemFiles({ passwdUsers: ['alice'], secretEnv: 'rbs_fake_deadbeef0001' }),
    '/app/exports/report.csv': 'col1,col2\n1,2\n',
    '/app/exports/sub/notes.txt': 'hello',
  })
}

test('normal read within jail returns content and emits nothing', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const vfs = mkVfs(oracle)
  runWithCtx(ctx(), () => {
    assert.equal(vfs.readWithin(JAIL, 'report.csv'), 'col1,col2\n1,2\n')
    assert.equal(vfs.readWithin(JAIL, 'sub/notes.txt'), 'hello')
    assert.equal(vfs.readWithin(JAIL, './report.csv'), 'col1,col2\n1,2\n')
  })
  assert.equal(oracle.events().filter((e) => e.kind === 'path_escape').length, 0)
})

test('plain and encoded traversal emits path_escape and still leaks the virtual file', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const vfs = mkVfs(oracle)
  const passwd = vfs.read('/etc/passwd')
  runWithCtx(ctx(), () => {
    assert.equal(vfs.readWithin(JAIL, '../../etc/passwd'), passwd)
    assert.equal(vfs.readWithin(JAIL, '%2e%2e%2f%2e%2e%2fetc%2fpasswd'), passwd)
    assert.equal(vfs.readWithin(JAIL, '..\\..\\etc\\passwd'), passwd)
    assert.equal(vfs.readWithin(JAIL, '/app/config/secrets.env'), vfs.read('/app/config/secrets.env'))
  })
  const escapes = oracle.events().filter((e) => e.kind === 'path_escape')
  assert.equal(escapes.length, 4)
  assert.ok(String(escapes[0].detail.resolved).startsWith('/etc/passwd'))
  assert.ok(String(escapes[0].sink).startsWith('vfs:'))
})

test('secrets file carries the rbs_ canary; list and exists behave', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const vfs = mkVfs(oracle)
  assert.match(vfs.read('/app/config/secrets.env') ?? '', /rbs_fake_deadbeef0001/)
  assert.equal(vfs.exists('/app/exports/report.csv'), true)
  assert.equal(vfs.exists('/nope'), false)
  assert.deepEqual(vfs.list('/app/exports'), ['/app/exports/report.csv'])
})
