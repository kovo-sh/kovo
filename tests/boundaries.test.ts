import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { setTimeout as delay } from 'node:timers/promises'
import { test } from 'node:test'
import { promisify } from 'node:util'
import { RequestBroker } from '../src/server/broker.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'

const exec = promisify(execFile)

async function fixture(handler: (request: IncomingMessage, response: ServerResponse) => void, host = '127.0.0.1') {
  const server = createServer(handler).listen(0, host)
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Fixture has no address.')
  return {
    url: `http://${host}:${address.port}`,
    close() {
      server.closeAllConnections()
      return new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

const northstar = 'https://northstar.example'
const allowed = { origin: northstar, canRead: (origin: string) => origin === northstar, audit: () => {} }
const publicAddress = { address: '93.184.216.34', family: 4 }

test('checks DNS destinations and redirect scope before dialing', async () => {
  const attempted: string[] = []
  const privateDestination = new RequestBroker({
    resolve: async () => [publicAddress, { address: '127.0.0.1', family: 4 }],
    transport: async url => { attempted.push(url.origin); throw new Error('Unexpected connection.') },
  })
  await assert.rejects(privateDestination.readPublicRoot(allowed, new AbortController().signal), /public addresses/)
  assert.equal(attempted.length, 0)
  const redirect = new RequestBroker({
    resolve: async () => [publicAddress],
    transport: async url => {
      attempted.push(url.origin)
      return { status: 302, headers: { location: 'https://docs.northstar.example/' } }
    },
  })
  await assert.rejects(redirect.readPublicRoot(allowed, new AbortController().signal), /outside.*scope/)
  assert.deepEqual(attempted, [northstar])
})

test('checks approved scope before reading a healthy fixture and before accepting its response', async () => {
  let respond: (() => void) | undefined
  const started = Promise.withResolvers<void>()
  let count = 0
  const target = await fixture((_request, response) => {
    count += 1
    respond = () => {
      response.writeHead(200, { 'Content-Type': 'text/html', 'Strict-Transport-Security': 'max-age=31536000' }).end('Fixture page')
    }
    if (count > 1) started.resolve()
    else respond()
  })
  try {
    let approved = true
    const grant = { ...allowed, canRead: (origin: string) => origin === northstar && approved }
    const broker = new RequestBroker({
      source: 'fixture response',
      resolve: async () => [publicAddress],
      transport: async (_url, _address, signal) => {
        const response = await fetch(target.url, { signal, redirect: 'error' })
        await response.body?.cancel()
        return { status: response.status, headers: Object.fromEntries(response.headers) }
      },
    })
    const signal = new AbortController().signal
    const first = await broker.readPublicRoot(grant, signal)
    assert.equal(first.transportMaxAge, 31_536_000)
    const pending = broker.readPublicRoot(grant, signal)
    const checked = assert.rejects(pending, /outside.*scope/)
    await started.promise
    approved = false
    respond?.()
    await checked
    await assert.rejects(broker.readPublicRoot(grant, signal), /outside.*scope/)
    assert.equal(count, 2)
  } finally {
    await target.close()
  }
})

test('runs pipelines in the production just-bash image with read-only evidence and bounded output', async () => {
  const backend = new LinuxWorkerBackend()
  const job = {
    assignmentId: randomUUID(),
    files: [
      { name: 'observed.json', content: '{"transportMaxAge":31536000,"source":"prepared"}' },
      { name: 'baseline.txt', content: '31536000\n' },
    ],
    outputs: ['result.txt'],
  }
  const result = await backend.run({
    ...job,
    command: [
      "jq -r '.transportMaxAge' /evidence/observed.json | sort > /work/actual.txt",
      "diff /evidence/baseline.txt /work/actual.txt || exit 9",
      "cat /root/.config/guardian.key 2>/dev/null && exit 11",
      "command -v curl >/dev/null && exit 12",
      "printf 'Matched baseline.\n' > /work/result.txt",
    ].join('\n'),
  }, new AbortController().signal)
  assert.equal(result.exitCode, 0, result.stderr)
  assert.equal(result.outputs['result.txt'], 'Matched baseline.\n')
  await assert.rejects(backend.run({
    ...job, command: "printf 'changed' > /evidence/observed.json",
  }, new AbortController().signal))
})

test('enforces the worker container boundary independently of just-bash', { timeout: 19_000 }, async () => {
  const gateway = (await exec('docker', ['network', 'inspect', 'bridge', '--format', '{{(index .IPAM.Config 0).Gateway}}'])).stdout.trim()
  const target = await fixture((_request, response) => response.end('healthy'), gateway)
  const assignmentId = randomUUID()
  const abort = new AbortController()
  const pending = new LinuxWorkerBackend().run({
    assignmentId, files: [], command: 'sleep 10', outputs: [],
  }, abort.signal)
  const stopped = assert.rejects(pending)
  try {
    assert.equal(await fetch(target.url, { signal: AbortSignal.timeout(3_000) }).then(res => res.text()), 'healthy')
    const filter = 'label=dev.guardian.assignment=' + assignmentId
    let container = ''
    for (let attempt = 0; attempt < 70 && !container; attempt += 1) {
      container = (await exec('docker', ['ps', '-q', '--filter', filter])).stdout.trim()
      if (!container) await delay(50)
    }
    assert.ok(container, 'The real worker container must be running during this check.')
    const config = JSON.parse((await exec('docker', ['inspect', '--format', '{{json .HostConfig}}', container])).stdout)
    assert.equal(config.NetworkMode, 'none')
    assert.equal(config.Privileged, false)
    assert.ok(config.ReadonlyRootfs)
    assert.ok(config.Memory >= 1 && config.Memory <= 256 * 1024 * 1024)
    assert.ok(config.NanoCpus >= 1 && config.NanoCpus <= 500_000_000)
    assert.ok(config.PidsLimit >= 1 && config.PidsLimit <= 48)
    assert.match(config.Tmpfs['/tmp'], /size=8m/)
    assert.equal(config.Binds, null)
    const probe = [
      'if (process.getuid() !== 10001) process.exit(11)',
      "if (require('node:fs').existsSync('/var/run/docker.sock')) process.exit(12)",
      "if (process.env.OPENROUTER_API_KEY || process.env.GUARDIAN_DATA_DIR) process.exit(13)",
      "fetch(process.argv[1], {signal: AbortSignal.timeout(700)}).then(() => process.exit(14), () => console.log('blocked'))",
    ].join('\n')
    const result = await exec('docker', ['exec', container, 'node', '-e', probe, target.url])
    assert.equal(result.stdout.trim(), 'blocked')
  } finally {
    abort.abort()
    await stopped
    await target.close()
  }
})
