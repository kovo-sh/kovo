import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { promisify } from 'node:util'
import { parseCliArgs } from '../scripts/cli.ts'
import { createApp } from './app.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { assertLocalLabAllowed, ingestLabTelemetry, LabRunner, parseAndSanitizeComposeYaml } from '../src/server/lab-runner.ts'
import { listProjectPersonas } from '../src/server/persona-vault.ts'
import { Store } from '../src/server/store.ts'

const exec = promisify(execFile)

const RAW_AWS = 'AKIAIOSFODNN7EXAMPLE'
const RAW_STRIPE = 'sk_live_TESTFIXTURE000000000000000000'
const RAW_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'

async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T> | T): Promise<T> {
  const prev: Record<string, string | undefined> = {}
  for (const [k, v] of Object.entries(vars)) {
    prev[k] = process.env[k]
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
  try {
    return await fn()
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

test('M5-1 compose & service sanitizer rejects unsafe directives, >6 services, and dangerous env keys before touching Docker', async t => {
  assert.throws(
    () => parseAndSanitizeComposeYaml('services:\n  app:\n    image: node:24-bookworm-slim\n    privileged: true\n'),
    /privileged|forbidden|unsafe/i,
  )
  assert.throws(
    () => parseAndSanitizeComposeYaml('services:\n  app:\n    image: node:24-bookworm-slim\n    network_mode: host\n'),
    /network_mode|forbidden|unsafe/i,
  )
  assert.throws(
    () => parseAndSanitizeComposeYaml('services:\n  app:\n    image: node:24-bookworm-slim\n    cap_add:\n      - SYS_ADMIN\n'),
    /cap_add|forbidden|unsafe/i,
  )
  assert.throws(
    () => parseAndSanitizeComposeYaml('services:\n  app:\n    image: node:24-bookworm-slim\n    ports:\n      - "8080:8080"\n'),
    /ports|forbidden|unsafe/i,
  )
  assert.throws(
    () => parseAndSanitizeComposeYaml('services:\n  app:\n    image: node:24-bookworm-slim\n    volumes:\n      - /etc:/host-etc\n'),
    /volume|bind|forbidden|unsafe/i,
  )

  const parsedOk = parseAndSanitizeComposeYaml([
    'services:',
    '  app:',
    '    image: node:24-bookworm-slim',
    '    command: node /app/app.js',
    '  sidecar:',
    '    image: node:24-bookworm-slim',
    '    command: ["node", "/app/sidecar.js"]',
  ].join('\n'))
  assert.equal(parsedOk.length, 2)
  assert.equal(parsedOk[0].name, 'app')
  assert.deepEqual(parsedOk[1].command, ['node', '/app/sidecar.js'])

  const dir = mkdtempSync(join(tmpdir(), 'kovo-m5-san-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const runner = new LabRunner()
  t.after(() => runner.stopAll())

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const tooMany = Array.from({ length: 7 }, (_, i) => ({ name: `svc_${i}`, image: 'node:24-bookworm-slim' }))
    await assert.rejects(
      runner.startLabTarget({ runId: randomUUID(), environment: 'local-lab', repoDir: dir, labConfig: { enabled: true, services: tooMany } }),
      /6|limit|max|container/i,
    )
    const badEnvs: Array<Record<string, string>> = [{ LD_PRELOAD: '/tmp/x.so' }, { PATH: '/tmp' }, { 'bad-key': '1' }]
    for (const badEnv of badEnvs) {
      await assert.rejects(
        runner.startLabTarget({ runId: randomUUID(), environment: 'local-lab', repoDir: dir, labConfig: { enabled: true, env: badEnv } }),
        /env|key|forbidden|unsafe/i,
      )
    }
  })

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: undefined }, () => {
    assert.throws(() => assertLocalLabAllowed('local-lab'), /KOVO_ALLOW_LOCAL_LAB/)
  })
})

test('M5-2 ingestLabTelemetry rejects public env, scrubs all secrets, enforces <= 64 KiB valid JSON, and updates endpoints.coverage_pct', t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m5-iast-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  assert.throws(
    () => ingestLabTelemetry({
      runId: randomUUID(),
      exchangeId: 'ex-pub',
      traceId: 'tr-pub',
      environment: 'public',
      telemetryDir: join(dir, 'evidence', 'lab-telemetry'),
      rawTelemetry: { routesHit: ['/'], newLinesCovered: 1 },
      secrets: [],
    }),
    /forbidden|local-lab|public/i,
  )

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'M5 Lab Telemetry',
    seeds: ['https://northstar.example'],
    environment: 'local-lab',
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId,
    goal: 'Test IAST ingestion',
    sourceMode: 'public',
    capabilityTier: 2,
    budgetUsd: 5,
    budgetRequests: 100,
    maxRpsPerOrigin: 5,
    workerConcurrency: 1,
    workerMaxTurns: 10,
  })

  storage.upsertEndpoint({
    runId,
    scopeRevision: 1,
    origin: 'https://northstar.example',
    method: 'GET',
    pathTemplate: '/api/orders/{orderId}',
    source: 'openapi',
    coveragePct: 0,
  })

  const personaSecret = 'SUPER_SECRET_PERSONA_TOKEN_XYZ'
  const telemetryDir = join(dir, 'evidence', 'lab-telemetry')
  const res = ingestLabTelemetry({
    runId,
    exchangeId: 'ex-m5-1',
    traceId: 'tr-m5-1',
    environment: 'local-lab',
    telemetryDir,
    secrets: [{ value: personaSecret, placeholder: '[persona:a:secret]' }],
    rawTelemetry: {
      routesHit: ['/api/orders/ord_42?include=items'],
      newLinesCovered: 8,
      sinkEvents: [
        {
          sink: 'pg.query',
          sql: `SELECT '${personaSecret}' '${RAW_AWS}' '${RAW_STRIPE}' '${RAW_JWT}'`,
          huge: 'Z'.repeat(120_000),
        },
      ],
      exceptions: [{ message: `Boom ${personaSecret}`, stack: 'S'.repeat(80_000) }],
    },
    storage,
  })

  assert.ok(existsSync(res.filePath))
  const diskSize = statSync(res.filePath).size
  assert.ok(diskSize <= 65_536, `Expected <= 65536 bytes, got ${diskSize}`)
  assert.equal(res.bytesWritten, diskSize)

  const text = readFileSync(res.filePath, 'utf8')
  const parsed = JSON.parse(text) as Record<string, unknown>
  assert.equal(parsed.exchangeId, 'ex-m5-1')
  assert.ok(!text.includes(personaSecret))
  assert.ok(!text.includes(RAW_AWS))
  assert.ok(!text.includes(RAW_STRIPE))
  assert.ok(!text.includes(RAW_JWT))

  const rows = storage.listLabTelemetry(runId)
  assert.equal(rows.length, 1)
  assert.equal(rows[0].hasUnhandledException, true)

  const eps = storage.listEndpoints(runId)
  assert.ok((eps[0].coveragePct ?? 0) > 0, 'Expected endpoint coveragePct to increase from IAST routesHit')
})

test('M5-3 Store rejects public iastEnabled and persists sandboxWriteAllowlist cleanly', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m5-store-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { id: pubId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Public Project',
    seeds: ['https://northstar.example'],
    environment: 'public',
  })
  assert.throws(
    () => storage.updateProjectLabConfig({
      requestId: randomUUID(),
      projectId: pubId,
      labConfig: { enabled: false, healthPath: '/', iastEnabled: true },
    }),
    /forbidden|public|local-lab/i,
  )

  const updated = storage.updateProjectSandboxWriteAllowlist({
    requestId: randomUUID(),
    projectId: pubId,
    sandboxWriteAllowlist: [{ origin: 'https://northstar.example', method: 'POST', pathPattern: '/api/orders' }],
  })
  assert.equal(updated.sandboxWriteAllowlist.length, 1)
  assert.equal(storage.project(pubId).sandboxWriteAllowlist[0]?.pathPattern, '/api/orders')
})

test('M5-4 LabRunner multi-service --internal stack + seedCommand -> 0600 Persona Vault + live Node IAST hook + 0 orphans', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m5-docker-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const repoDir = join(dir, 'repo')
  mkdirSync(repoDir, { recursive: true })
  writeFileSync(join(repoDir, 'sidecar.js'), [
    "const http = require('http')",
    "http.createServer((req, res) => {",
    "  if (req.url === '/health') return res.end('ok')",
    "  res.end('SIDECAR_LIVE')",
    "}).listen(9091, '0.0.0.0')",
  ].join('\n'))
  writeFileSync(join(repoDir, 'app.js'), [
    "const http = require('http')",
    "http.createServer(async (req, res) => {",
    "  if (req.url === '/health') return res.end('ok')",
    "  if (req.url === '/sidecar') {",
    "    const r = await fetch('http://sidecar:9091/')",
    "    return res.end(await r.text())",
    "  }",
    "  const u = new URL(req.url || '/', 'http://localhost')",
    "  if ((u.searchParams.get('id') || '').includes(\"'\")) { res.statusCode = 500; return res.end('SQLITE_ERROR: near syntax error') }",
    "  res.end('APP_LIVE')",
    "}).listen(8080, '0.0.0.0')",
  ].join('\n'))
  writeFileSync(join(repoDir, 'seed.js'), [
    "console.log(JSON.stringify({ personas: [{ handle: 'seeded_a', roleLabel: 'Tenant A', authKind: 'bearer', secret: 'seeded-secret-a' }] }))",
  ].join('\n'))

  const storage = new Store(join(dir, 'data'))
  t.after(() => storage.close())
  const runner = new LabRunner()
  t.after(() => runner.stopAll())

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const { id: projectId } = storage.createProject({
      requestId: randomUUID(),
      name: 'M5 Docker Stack',
      seeds: ['http://127.0.0.1:8080'],
      environment: 'local-lab',
    })
    const runId = randomUUID()
    const handle = await runner.startLabTarget({
      runId,
      environment: 'local-lab',
      repoDir,
      storage,
      projectId,
      labConfig: {
        enabled: true,
        internalPort: 8080,
        healthPath: '/health',
        seedCommand: 'node /app/seed.js',
        iastEnabled: true,
        iastRuntime: 'node',
        services: [
          { name: 'app', image: 'node:24-bookworm-slim', command: 'node /app/app.js', internalPort: 8080, healthPath: '/health' },
          { name: 'sidecar', image: 'node:24-bookworm-slim', command: 'node /app/sidecar.js', internalPort: 9091, healthPath: '/health' },
        ],
      },
      signal: AbortSignal.timeout(90_000),
    })

    assert.equal(handle.containerNames.length, 2)
    assert.equal(await (await fetch(`${handle.origin}/sidecar`)).text(), 'SIDECAR_LIVE')
    assert.equal(handle.seededPersonas.length, 1)
    assert.equal(handle.seededPersonas[0].handle, 'seeded_a')
    assert.equal(listProjectPersonas(storage, projectId).some(p => p.handle === 'seeded_a'), true)

    const broker = new RequestBroker({ rejectUnauthorized: false })
    const traceId = `m5-trace-${randomUUID().slice(0, 8)}`
    const ex = await broker.executeHttp(
      { origin: handle.origin, method: 'GET', pathAndQuery: "/api/items?id=1'", traceId } as never,
      { origin: handle.origin, tier: 2, maxRpsPerOrigin: 20, allowLocalLab: true, canRead: o => o === handle.origin, audit: () => {} },
      AbortSignal.timeout(15_000),
    )
    assert.equal(ex.status, 500)
    assert.ok(handle.telemetryDir && existsSync(handle.telemetryDir))
    const traceFiles = readdirSync(handle.telemetryDir)
    assert.ok(traceFiles.some(f => f.includes(traceId)), `Expected trace file for ${traceId}, got ${traceFiles.join(', ')}`)
    const traceContent = JSON.parse(readFileSync(join(handle.telemetryDir, traceFiles.find(f => f.includes(traceId))!), 'utf8')) as {
      sinkEvents: Array<{ sink: string }>
    }
    assert.ok(traceContent.sinkEvents.some(ev => ev.sink === 'sql.query'))

    await runner.stopAll()
    const leftC = (await exec('docker', ['ps', '-aq', '--filter', `label=dev.kovo.run=${runId}`])).stdout.trim()
    const leftN = (await exec('docker', ['network', 'ls', '-q', '--filter', `name=${handle.networkName}`])).stdout.trim()
    assert.equal(leftC, '')
    assert.equal(leftN, '')
  })
})

test('M5-5 cli.ts parses v4 local-lab flags cleanly', () => {
  const opts = parseCliArgs([
    'scan', '--local-lab', '--repo', '/tmp/demo', '--compose', 'docker-compose.yml',
    '--lab-port', '3000', '--lab-health', '/healthz', '--lab-seed', 'node seed.mjs', '--iast',
    '--sarif', '/tmp/out.sarif', '--tier', '2',
  ])
  assert.equal(opts.localLab, true)
  assert.equal(opts.composeFile, 'docker-compose.yml')
  assert.equal(opts.labPort, 3000)
  assert.equal(opts.labHealthPath, '/healthz')
  assert.equal(opts.labSeedCommand, 'node seed.mjs')
  assert.equal(opts.iast, true)
  assert.equal(opts.sarifPath, '/tmp/out.sarif')
})

test('M5-6 Surface Graph SSR route renders endpoints, endpoint_params, and api_dependencies from SQLite', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m5-surface-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  let runId = ''
  let consumerId = ''
  {
    const storage = new Store(dir)
    const { id: projectId } = storage.createProject({
      requestId: randomUUID(),
      name: 'Surface SSR Check',
      seeds: ['https://northstar.example'],
      environment: 'public',
    })
    runId = storage.createRun({
      requestId: randomUUID(),
      projectId,
      goal: 'Verify Surface Graph rendering',
      sourceMode: 'public',
      capabilityTier: 2,
      budgetUsd: 5,
      budgetRequests: 100,
      maxRpsPerOrigin: 5,
      workerConcurrency: 1,
      workerMaxTurns: 10,
    }).id
    const producer = storage.upsertEndpoint({
      runId,
      scopeRevision: 1,
      origin: 'https://northstar.example',
      method: 'POST',
      pathTemplate: '/api/orders',
      source: 'openapi',
      riskScore: 85,
    })
    const consumer = storage.upsertEndpoint({
      runId,
      scopeRevision: 1,
      origin: 'https://northstar.example',
      method: 'GET',
      pathTemplate: '/api/orders/{orderId}',
      source: 'openapi',
      riskScore: 90,
      coveragePct: 45,
    })
    storage.upsertEndpointParam({
      runId,
      endpointId: consumer.id,
      name: 'orderId',
      location: 'path',
      isObjectId: true,
      source: 'openapi',
    })
    storage.upsertEndpointParam({
      runId,
      endpointId: consumer.id,
      name: 'include',
      location: 'query',
      source: 'openapi',
    })
    storage.recordApiDependency({
      runId,
      producerEndpointId: producer.id,
      consumerEndpointId: consumer.id,
      resourceKey: 'orderId',
      personaHandle: 'user_a',
      observedTransitions: ['draft', 'submitted'],
    })
    consumerId = consumer.id
    storage.close()
  }

  const app = await createApp({}, dir)
  t.after(() => app.dispose())
  await app.start()
  const token = readFileSync(join(dir, 'local-session'), 'utf8').trim()
  const resp = await fetch(`${app.url}/runs/${runId}?view=surface&sel=endpoint:${consumerId}`, {
    headers: { Cookie: `kovo_local=${token}` },
  })
  assert.equal(resp.status, 200)
  const html = await resp.text()
  const plain = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ')
  assert.ok(plain.includes('/api/orders'))
  assert.ok(plain.includes('/api/orders/{orderId}'))
  assert.match(plain, /\borderId\b/)
  assert.match(plain, /\binclude\b/)
  assert.match(plain, /\b(?:query|path)\b/i)
  assert.match(plain, /API dependencies/i)
  assert.match(plain, /(?:GET|POST)\s+\/api\/orders[\s\S]*?(?:→|->)[\s\S]*?\/api\/orders\/\{?orderId\}?/i)
})
