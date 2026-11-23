/**
 * v6 Phase 3: async public OOB relay.
 *
 * Covers the two-stage correlation contract (3 s immediate check + durable `pending_oob`
 * late promotion), restart resume, idempotent callback accounting, callback integrity
 * (token/source/artifact binding), fail-closed public profiles, and authoritative DNS hooks.
 */
import assert from 'node:assert/strict'
import { createSocket } from 'node:dgram'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, test } from 'node:test'

import { CanaryBroker } from '../src/server/canary-broker.ts'
import {
  OobProfileError,
  OobRelay,
  assertPublicProfileStartable,
  ipInAllowlist,
  resolveOobRelayProfile,
} from '../src/server/oob-relay.ts'
import type { OobDnsAnswer, OobDnsProvider, OobRejection } from '../src/server/oob-relay.ts'

class FakeClock {
  value = 1_700_000_000_000
  now = (): number => this.value
  advance(ms: number): void {
    this.value += ms
  }
}

const tokenA = `guardian-canary-${'a'.repeat(24)}`
const tokenB = `guardian-canary-${'b'.repeat(24)}`

const tempDirs: string[] = []
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-v6-oob-'))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function binding(over: Partial<{ runId: string; assignmentId: string; canaryId: string; token: string; artifact: string }> = {}) {
  return {
    runId: 'run-1',
    assignmentId: 'assign-1',
    canaryId: 'canary-1',
    token: tokenA,
    artifact: 'ex-proof-1',
    ...over,
  }
}

function fakeSleep(clock: FakeClock) {
  return async (ms: number) => clock.advance(ms)
}

// ============================================================================
// Two-stage async correlation
// ============================================================================

describe('v6 OOB: two-stage async correlation', () => {
  test('immediate hit promotes during the short 3 s check', async () => {
    const clock = new FakeClock()
    const relay = new OobRelay({ directory: tempDir(), now: clock.now })
    try {
      relay.registerCanary({ token: tokenA, canaryId: 'canary-1', runId: 'run-1', assignmentId: 'assign-1' })
      const recorded = relay.recordCallback({
        token: tokenA,
        artifact: 'ex-proof-1',
        sourceIp: '203.0.113.9',
        receivedAt: clock.now(),
        method: 'POST',
        path: '/webhook',
      })
      assert.equal(recorded.accepted, true)

      const result = await relay.correlate(binding(), {
        immediateMs: 3_000,
        pollMs: 150,
        sleep: fakeSleep(clock),
      })
      assert.equal(result.matched, true)
      assert.equal(result.stage, 'immediate')
      assert.equal(result.subscription.status, 'promoted')
      assert.equal(result.callback?.callbackId, recorded.accepted ? recorded.callback.callbackId : null)
      // No durable subscription left behind once the immediate stage matched.
      assert.equal(relay.pending().length, 0)
      const status = relay.status()
      assert.equal(status.delivered, 1)
      assert.equal(status.promoted, 1)
      assert.equal(status.pending, 0)
    } finally {
      relay.close()
    }
  })

  test('late callback is promoted after 15 s via pending_oob (fake clock)', async () => {
    const clock = new FakeClock()
    const relay = new OobRelay({ directory: tempDir(), now: clock.now })
    try {
      relay.registerCanary({ token: tokenA, canaryId: 'canary-1', runId: 'run-1', assignmentId: 'assign-1' })

      const immediate = await relay.correlate(binding(), {
        immediateMs: 3_000,
        pollMs: 150,
        sleep: fakeSleep(clock),
      })
      assert.equal(immediate.matched, false)
      assert.equal(immediate.stage, 'pending')
      assert.equal(relay.pending('run-1').length, 1)
      assert.equal(relay.pending()[0].token, tokenA)

      clock.advance(12_000) // 15 s after subscription creation
      const recorded = relay.recordCallback({
        token: tokenA,
        artifact: 'ex-proof-1',
        sourceIp: '198.51.100.7',
        receivedAt: clock.now(),
        method: 'POST',
        path: '/render.pdf',
      })
      assert.equal(recorded.accepted, true)

      const promoted = relay.promoteLate()
      assert.equal(promoted.length, 1)
      assert.equal(promoted[0].stage, 'late')
      assert.equal(promoted[0].latencyMs, 15_000)
      assert.equal(promoted[0].subscription.status, 'promoted')
      assert.equal(promoted[0].subscription.runId, 'run-1')
      assert.equal(promoted[0].callback.token, tokenA)
      assert.equal(relay.pending().length, 0)

      // Promotion is idempotent: a second sweep cannot double-count the same callback.
      assert.equal(relay.promoteLate().length, 0)
      assert.equal(relay.status().promoted, 1)
      assert.equal(relay.status().delivered, 1)
    } finally {
      relay.close()
    }
  })

  test('restart resumes the durable subscription from disk', async () => {
    const clock = new FakeClock()
    const dir = tempDir()
    const first = new OobRelay({ directory: dir, now: clock.now })
    first.registerCanary({ token: tokenA, canaryId: 'canary-1', runId: 'run-1', assignmentId: 'assign-1' })
    const immediate = await first.correlate(binding(), { immediateMs: 0 })
    assert.equal(immediate.stage, 'pending')
    const subscriptionId = immediate.subscription.id
    first.close()

    // Simulate a process restart: a brand-new relay opens the same directory.
    const second = new OobRelay({ directory: dir, now: clock.now })
    try {
      const resumed = second.pending('run-1')
      assert.equal(resumed.length, 1)
      assert.equal(resumed[0].id, subscriptionId)
      assert.equal(resumed[0].artifact, 'ex-proof-1')

      clock.advance(20_000)
      const recorded = second.recordCallback({
        token: tokenA,
        artifact: 'ex-proof-1',
        sourceIp: '192.0.2.44',
        receivedAt: clock.now(),
      })
      assert.equal(recorded.accepted, true)
      const promoted = second.promoteLate({ runId: 'run-1' })
      assert.equal(promoted.length, 1)
      assert.equal(promoted[0].subscription.id, subscriptionId)
      assert.equal(second.pending().length, 0)
    } finally {
      second.close()
    }
  })

  test('duplicate callback delivery is counted once (idempotent callback id)', () => {
    const clock = new FakeClock()
    const relay = new OobRelay({ now: clock.now })
    try {
      relay.registerCanary({ token: tokenA, canaryId: 'canary-1', runId: 'run-1' })
      const input = {
        callbackId: 'cb-dup-1',
        token: tokenA,
        artifact: 'ex-proof-1',
        sourceIp: '198.51.100.10',
        method: 'POST',
        path: '/hook',
      }
      const first = relay.recordCallback(input)
      const second = relay.recordCallback(input)
      assert.equal(first.accepted, true)
      assert.equal(second.accepted, true)
      assert.equal(second.duplicate, true)
      assert.equal(relay.check({ token: tokenA }).callbacks.length, 1)
      assert.equal(relay.status().delivered, 1)
    } finally {
      relay.close()
    }
  })

  test('awaitAny resolves an already-delivered callback', async () => {
    const relay = new OobRelay()
    try {
      relay.registerCanary({ token: tokenA, canaryId: 'canary-1', runId: 'run-1' })
      relay.recordCallback({ token: tokenA, artifact: 'ex-1', sourceIp: '198.51.100.3' })
      const result = await relay.awaitAny({ token: tokenA }, { timeoutMs: 200, pollMs: 25 })
      assert.equal(result.matched, true)
      assert.equal(result.callback?.token, tokenA)
    } finally {
      relay.close()
    }
  })
})

// ============================================================================
// Correlation integrity
// ============================================================================

describe('v6 OOB: correlation integrity', () => {
  test('mismatched token is rejected and logged as oob_rejected', () => {
    const relay = new OobRelay()
    try {
      relay.registerCanary({ token: tokenA, canaryId: 'canary-1', runId: 'run-1' })
      const result = relay.recordCallback({
        token: tokenB,
        canaryId: 'canary-1',
        artifact: 'ex-1',
        sourceIp: '198.51.100.20',
      })
      assert.equal(result.accepted, false)
      if (!result.accepted) assert.equal(result.rejection.reason, 'token_mismatch')
      assert.equal(relay.status().delivered, 0)
      assert.equal(relay.status().rejected, 1)
      const logged = relay.rejections()
      assert.equal(logged[0].event, 'oob_rejected')
      assert.equal(logged[0].reason, 'token_mismatch')
    } finally {
      relay.close()
    }
  })

  test('callback from a non-allowlisted source is rejected', () => {
    const clock = new FakeClock()
    const relay = new OobRelay({ now: clock.now })
    try {
      relay.registerCanary({ token: tokenA, canaryId: 'canary-1', runId: 'run-1' })
      relay.subscribe({ ...binding(), allowlist: ['198.51.100.0/24'] })
      const rejected = relay.recordCallback({
        token: tokenA,
        artifact: 'ex-proof-1',
        sourceIp: '203.0.113.50',
      })
      assert.equal(rejected.accepted, false)
      if (!rejected.accepted) assert.equal(rejected.rejection.reason, 'source_not_allowlisted')
      const allowed = relay.recordCallback({
        token: tokenA,
        artifact: 'ex-proof-1',
        sourceIp: '::ffff:198.51.100.7',
      })
      assert.equal(allowed.accepted, true)
      assert.equal(ipInAllowlist('10.1.2.3', ['10.0.0.0/8']), true)
      assert.equal(ipInAllowlist('11.1.2.3', ['10.0.0.0/8']), false)
    } finally {
      relay.close()
    }
  })

  test('callback must carry the causal artifact bound to the subscription', () => {
    const relay = new OobRelay()
    try {
      relay.registerCanary({ token: tokenA, canaryId: 'canary-1', runId: 'run-1' })
      relay.subscribe({ ...binding(), artifact: 'ex-proof-1' })
      const missing = relay.recordCallback({ token: tokenA, sourceIp: '198.51.100.8' })
      assert.equal(missing.accepted, false)
      if (!missing.accepted) assert.equal(missing.rejection.reason, 'artifact_missing')
      const wrong = relay.recordCallback({ token: tokenA, artifact: 'ex-other', sourceIp: '198.51.100.8' })
      assert.equal(wrong.accepted, false)
      if (!wrong.accepted) assert.equal(wrong.rejection.reason, 'artifact_mismatch')
      const good = relay.recordCallback({
        token: tokenA, artifact: 'ex-proof-1', sourceIp: '198.51.100.8', callbackId: 'cb-artifact-ok',
      })
      assert.equal(good.accepted, true)
    } finally {
      relay.close()
    }
  })
})

// ============================================================================
// Relay profiles: loopback default, fail-closed public profile
// ============================================================================

describe('v6 OOB: relay profiles', () => {
  test('loopback mode is the default and never opens public listeners', async () => {
    const broker = new CanaryBroker()
    try {
      assert.equal(broker.relayProfile().mode, 'loopback')
      assert.equal(broker.relayProfile().publicEnabled, false)

      const info = await broker.startListener({ host: '127.0.0.1', port: 0 })
      assert.equal(info.running, true)
      assert.equal(info.host, '127.0.0.1')
      assert.ok(info.localBaseUrl?.startsWith('http://127.0.0.1:'))
      assert.equal(info.publicProfileActive, false)
      assert.equal(info.httpsRunning, false)
      assert.equal(info.dnsTcpRunning, false)
      assert.equal(broker.relayProfile().mode, 'loopback')

      const canary = broker.mintCanary('run-local', 'ssrf-probe', 'https://target.example')
      assert.equal(canary.synthetic, false)
      const response = await fetch(`${canary.httpUrl}?probe=ok`, { signal: AbortSignal.timeout(5_000) })
      assert.equal(response.status, 200)
      assert.equal(await response.text(), 'guardian-canary-ok')
      assert.equal(broker.checkCanary(canary.token).hit, true)

      const status = broker.relayStatus()
      assert.equal(status.mode, 'loopback')
      assert.equal(status.delivered, 1)
      assert.equal(status.listener.publicProfileActive, false)
    } finally {
      await broker.stopListener()
      broker.closeOob()
    }
  })

  test('public profile refuses to activate without explicit operator config', async () => {
    const previous = process.env.GUARDIAN_OOB_PUBLIC
    delete process.env.GUARDIAN_OOB_PUBLIC
    const broker = new CanaryBroker()
    try {
      const defaults = resolveOobRelayProfile({}, {})
      assert.equal(defaults.mode, 'loopback')
      assert.equal(defaults.publicEnabled, false)
      assert.throws(() => assertPublicProfileStartable(defaults), OobProfileError)
      await assert.rejects(broker.startPublicProfile(), OobProfileError)

      // Explicitly requested but incomplete: stays in public mode but fails closed.
      const incomplete = resolveOobRelayProfile(
        { enabled: true, publicBaseUrl: 'http://oob.example' },
        {},
      )
      assert.equal(incomplete.mode, 'public')
      assert.equal(incomplete.publicEnabled, false)
      assert.ok(incomplete.problems.some(problem => problem.includes('https')))
      assert.ok(incomplete.problems.some(problem => problem.includes('DNS')))
      assert.throws(() => assertPublicProfileStartable(incomplete), OobProfileError)

      // Complete operator config (ACME hook + authoritative DNS hook) becomes startable.
      const complete = resolveOobRelayProfile({
        enabled: true,
        publicBaseUrl: 'https://oob.example',
        https: { acme: { loadCertificate: async () => ({ cert: 'cert', key: 'key' }) } },
        dns: { domain: 'oob.example', provider: { resolve: () => null } },
      }, {})
      assert.equal(complete.publicEnabled, true)
      assert.equal(complete.https.certificate, 'acme-hook')
      assert.equal(complete.dns.authoritative, true)
      assert.doesNotThrow(() => assertPublicProfileStartable(complete))
    } finally {
      if (previous === undefined) delete process.env.GUARDIAN_OOB_PUBLIC
      else process.env.GUARDIAN_OOB_PUBLIC = previous
      await broker.stopListener()
      broker.closeOob()
    }
  })

  test('setting a public base URL does not auto-open public listeners', async () => {
    const broker = new CanaryBroker()
    try {
      const info = await broker.startListener({ host: '127.0.0.1', port: 0, publicBaseUrl: 'https://oob.example' })
      assert.equal(info.publicProfileActive, false)
      assert.equal(info.httpsRunning, false)
      assert.doesNotMatch(info.localBaseUrl ?? '', /oob\.example/)
    } finally {
      await broker.stopListener()
      broker.closeOob()
    }
  })

  test('explicit operator config activates the public profile and serves the ACME hook', async () => {
    const acmeCalls: string[] = []
    const broker = new CanaryBroker()
    try {
      const info = await broker.startPublicProfile({ https: false, dnsTcp: false }, {
        enabled: true,
        publicBaseUrl: 'https://oob.example',
        http: { host: '127.0.0.1', port: 0 },
        https: {
          port: 0,
          acme: {
            loadCertificate: async () => ({ cert: 'unused', key: 'unused' }),
            answerHttpChallenge: path => {
              acmeCalls.push(path)
              return { body: 'acme-token-value' }
            },
          },
        },
        dns: {
          domain: 'oob.example',
          host: '127.0.0.1',
          udpPort: 0,
          tcpPort: 0,
          provider: { resolve: () => null },
        },
      })
      assert.equal(info.publicProfileActive, true)
      assert.ok(info.localBaseUrl)

      const challenge = await fetch(`${info.localBaseUrl}/.well-known/acme-challenge/token`, {
        signal: AbortSignal.timeout(5_000),
      })
      assert.equal(challenge.status, 200)
      assert.equal(await challenge.text(), 'acme-token-value')
      assert.deepEqual(acmeCalls, ['/.well-known/acme-challenge/token'])

      const canary = broker.mintCanary('run-public', 'oob-probe', 'https://target.example')
      const callback = await fetch(`${info.localBaseUrl}/c/${canary.token}`, { signal: AbortSignal.timeout(5_000) })
      assert.equal(await callback.text(), 'guardian-canary-ok')
      assert.equal(broker.checkCanary(canary.token).hit, true)
      assert.equal(broker.relayStatus().publicEnabled, true)
    } finally {
      await broker.stopListener()
      broker.closeOob()
    }
  })
})

// ============================================================================
// Authoritative DNS hooks (TXT + A), UDP provider interface
// ============================================================================

function dnsQuery(id: number, name: string, type: number): Buffer {
  const labels = name.split('.').filter(Boolean)
  const qname = Buffer.concat([
    ...labels.map(label => Buffer.concat([Buffer.from([label.length]), Buffer.from(label, 'ascii')])),
    Buffer.from([0]),
  ])
  const header = Buffer.alloc(12)
  header.writeUInt16BE(id, 0)
  header.writeUInt16BE(0x0100, 2)
  header.writeUInt16BE(1, 4)
  const tail = Buffer.alloc(4)
  tail.writeUInt16BE(type, 0)
  tail.writeUInt16BE(1, 2)
  return Buffer.concat([header, qname, tail])
}

function udpQuery(port: number, message: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = createSocket('udp4')
    const timer = setTimeout(() => {
      socket.close()
      reject(new Error('DNS query timed out'))
    }, 3_000)
    socket.on('message', response => {
      clearTimeout(timer)
      socket.close()
      resolve(response)
    })
    socket.on('error', error => {
      clearTimeout(timer)
      socket.close()
      reject(error)
    })
    socket.send(message, port, '127.0.0.1')
  })
}

describe('v6 OOB: authoritative DNS hooks', () => {
  test('DNS provider hook is invoked for TXT and A queries', async () => {
    const calls: Array<{ name: string; type: number; typeName: string }> = []
    const provider: OobDnsProvider = {
      name: 'test-authoritative',
      resolve: query => {
        calls.push({ name: query.name, type: query.type, typeName: query.typeName })
        if (query.type === 16) return { type: 'TXT', value: 'guardian-canary-ok' } satisfies OobDnsAnswer
        if (query.type === 1) return { type: 'A', value: '127.0.0.1' } satisfies OobDnsAnswer
        return null
      },
    }

    const relay = new OobRelay({
      profile: { enabled: true, publicBaseUrl: 'https://oob.example', dns: { domain: 'oob.example', provider } },
    })
    try {
      const txt = await relay.resolveDns({ name: 'verify.oob.example', type: 16, typeName: 'TXT' })
      assert.deepEqual(txt, { type: 'TXT', value: 'guardian-canary-ok' })
      const address = await relay.resolveDns({ name: 'verify.oob.example', type: 1, typeName: 'A' })
      assert.deepEqual(address, { type: 'A', value: '127.0.0.1' })
      assert.deepEqual(calls.map(call => call.typeName), ['TXT', 'A'])
    } finally {
      relay.close()
    }

    const broker = new CanaryBroker({ dnsDomain: 'oob.example' })
    try {
      const info = await broker.startListener({
        host: '127.0.0.1',
        port: 0,
        enableDns: true,
        dnsHost: '127.0.0.1',
        dnsPort: 0,
        dnsDomain: 'oob.example',
        dnsProvider: provider,
      })
      assert.ok(info.dnsPort)
      const before = calls.length

      const txtResponse = await udpQuery(info.dnsPort!, dnsQuery(0x1234, 'verify.oob.example', 16))
      assert.equal(txtResponse.readUInt16BE(0), 0x1234)
      assert.equal(txtResponse.readUInt16BE(6), 1) // ANCOUNT
      const aResponse = await udpQuery(info.dnsPort!, dnsQuery(0x5678, 'verify.oob.example', 1))
      assert.equal(aResponse.readUInt16BE(6), 1)

      assert.equal(calls.length - before, 2)
      assert.deepEqual(calls.slice(-2).map(call => call.typeName), ['TXT', 'A'])
    } finally {
      await broker.stopListener()
      broker.closeOob()
    }
  })
})
