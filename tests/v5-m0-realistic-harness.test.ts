// M0 acceptance: real-Execution realistic-bench harness.
// Covers CLI parsing, mode->briefing mapping, persisted-finding translation, grader
// integration (without booting Execution) and bounded/clean shutdown.
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import {
  existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync, statSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { promisify } from 'node:util'

import type {
  Briefing, GroundTruth, OracleEvent, RequestLogEntry, Scorecard,
} from '../benchmarks/realistic-bench/lib/types.ts'
import { gradeRun } from '../benchmarks/realistic-bench/run.ts'
import type { Finding } from '../src/domain.ts'
import { privateModelProfiles } from '../src/server/model-settings.ts'
import { Store } from '../src/server/store.ts'
import {
  PreflightError, assertAgenticPreflight, briefingToOpenApi, buildTelemetry, cellKeys,
  describeModelMode, detectWorkerSessions, endpointsFromReplaySpec, isInertAgenticRun, openCellStore,
  parseRealisticArgs, pickLoginPath, planCell, prepareIsolatedDataDir, probeLoginPath,
  shouldIsolateDataDir, stopEngine, summarizeAssignments, translateFindings,
} from '../scripts/benchmark-realistic.ts'

const execFileAsync = promisify(execFile)
const repoRoot = resolve(new URL('..', import.meta.url).pathname)

// ---------------------------------------------------------------------------------------------
// CLI parsing
// ---------------------------------------------------------------------------------------------

test('CLI: defaults are local-lab safe and deterministic', () => {
  const args = parseRealisticArgs([], {})
  assert.deepEqual(args.apps, ['acme-saas', 'shopflow', 'opsportal'])
  assert.deepEqual(args.seeds, [1])
  assert.equal(args.mode, 'grey-box')
  assert.equal(args.heldOut, false)
  assert.equal(args.budgetUsd, 5)
  assert.equal(args.concurrency, 1)
  assert.equal(args.noLlm, false)
  assert.equal(args.verifier, 'auto')
  assert.match(args.outDir, /\.kovo\/realistic-bench$/)
})

test('CLI: app, seed sweep, mode, budget, duration and out-dir parse', () => {
  const args = parseRealisticArgs([
    '--app', 'opsportal', '--seeds', '1,2,3', '--mode', 'white-box',
    '--budget-usd', '20', '--max-duration-ms', '60000', '--out-dir', '/tmp/rb',
    '--concurrency', '2', '--no-llm', '--verifier', 'local-jq',
  ], {})
  assert.deepEqual(args.apps, ['opsportal'])
  assert.deepEqual(args.seeds, [1, 2, 3])
  assert.equal(args.mode, 'white-box')
  assert.equal(args.budgetUsd, 20)
  assert.equal(args.maxDurationMs, 60_000)
  assert.equal(args.outDir, '/tmp/rb')
  assert.equal(args.concurrency, 2)
  assert.equal(args.noLlm, true)
  assert.equal(args.verifier, 'local-jq')
})

test('CLI: --app all expands to all three apps and dedupes seeds', () => {
  const args = parseRealisticArgs(['--app', 'all', '--seeds', '4,4,5'], {})
  assert.deepEqual(args.apps, ['acme-saas', 'shopflow', 'opsportal'])
  assert.deepEqual(args.seeds, [4, 5])
  assert.deepEqual(cellKeys(args), [
    { app: 'acme-saas', seed: 4 }, { app: 'acme-saas', seed: 5 },
    { app: 'shopflow', seed: 4 }, { app: 'shopflow', seed: 5 },
    { app: 'opsportal', seed: 4 }, { app: 'opsportal', seed: 5 },
  ])
})

test('CLI: KOVO_DATA_DIR is the default data dir and --allow-inert-workers parses', () => {
  const args = parseRealisticArgs(['--allow-inert-workers'], { KOVO_DATA_DIR: '/tmp/kovo-data' })
  assert.equal(args.dataDir, '/tmp/kovo-data')
  assert.equal(args.allowInertWorkers, true)
  assert.equal(args.isolateDataDir, false)
  assert.equal(args.keepDataDirs, false)
  const override = parseRealisticArgs(['--data-dir', '/tmp/explicit'], { KOVO_DATA_DIR: '/tmp/kovo-data' })
  assert.equal(override.dataDir, '/tmp/explicit')
  assert.equal(override.allowInertWorkers, false)
  const isolation = parseRealisticArgs(['--isolate-data-dir', '--keep-data-dirs'], {})
  assert.equal(isolation.isolateDataDir, true)
  assert.equal(isolation.keepDataDirs, true)
})

test('CLI: held-out requires salt and a held-out seed range', () => {
  assert.throws(() => parseRealisticArgs(['--held-out', '--seed', '1000001'], {}), /KOVO_RB_HELDOUT_SALT/)
  assert.throws(
    () => parseRealisticArgs(['--held-out', '--seed', '10'], { KOVO_RB_HELDOUT_SALT: 'x'.repeat(16) }),
    />= 1000000/,
  )
  assert.throws(() => parseRealisticArgs(['--seed', '1000001'], {}), /add --held-out/)
  const ok = parseRealisticArgs(['--held-out', '--seed', '1000001'], { KOVO_RB_HELDOUT_SALT: 'x'.repeat(16) })
  assert.equal(ok.heldOut, true)
  assert.deepEqual(ok.seeds, [1_000_001])
})

test('CLI: rejects unknown flags, invalid modes, budgets and seed combinations', () => {
  assert.throws(() => parseRealisticArgs(['--bogus'], {}), /unknown flag/)
  assert.throws(() => parseRealisticArgs(['--mode', 'purple-box'], {}), /--mode/)
  assert.throws(() => parseRealisticArgs(['--budget-usd', '0'], {}), /--budget-usd/)
  assert.throws(() => parseRealisticArgs(['--budget-usd', '501'], {}), /--budget-usd/)
  assert.throws(() => parseRealisticArgs(['--seed', '1', '--seeds', '2'], {}), /either --seed or --seeds/)
  assert.throws(() => parseRealisticArgs(['--concurrency', '0'], {}), /--concurrency/)
})

test('CLI: --help exits 0 and prints the usage contract', async () => {
  const { stdout } = await execFileAsync(process.execPath, ['scripts/benchmark-realistic.ts', '--help'], {
    cwd: repoRoot,
    env: { ...process.env },
  })
  assert.match(stdout, /Kovo(?: Hunter)? realistic-bench \(real Execution loop\)/)
  assert.match(stdout, /benchmark_runs row/)
  assert.match(stdout, /KOVO_RB_HELDOUT_SALT/)
})

// ---------------------------------------------------------------------------------------------
// mode -> briefing mapping
// ---------------------------------------------------------------------------------------------

function briefing(mode: Briefing['mode']): Briefing {
  const blackBoxPersonas: Briefing['personas'] = [
    { id: 'persona_a', email: 'a@example.test', password: 'pw-a', tenant: 't1', role: 'admin' },
    { id: 'persona_b', email: 'b@example.test', password: 'pw-b', tenant: 't2', role: 'member' },
  ]
  const greyPersonas: Briefing['personas'] = [
    ...blackBoxPersonas,
    { id: 'admin', email: 'admin@example.test', password: 'pw-c', tenant: 't1', role: 'admin' },
    { id: 'viewer', email: 'viewer@example.test', password: 'pw-d', tenant: 't2', role: 'viewer' },
  ]
  const base: Briefing = {
    app: 'acme-saas',
    mode,
    origin: 'http://127.0.0.1:4000',
    personas: mode === 'black-box' ? blackBoxPersonas : greyPersonas,
  }
  if (mode !== 'black-box') {
    base.apiReference = [
      { routeKey: 'login', method: 'POST', path: '/api/auth/login', params: [] },
      { routeKey: 'getInvoice', method: 'GET', path: '/api/invoices/:invoiceId', params: ['invoiceId'] },
    ]
  }
  if (mode === 'white-box') base.sourceDir = '/tmp/realistic-bench/acme/src'
  return base
}

test('mapping: black-box exposes only two personas and no specs/source', () => {
  const b = briefing('black-box')
  const plan = planCell(b, pickLoginPath(b))
  assert.equal(plan.personas.length, 2)
  assert.equal(plan.briefing.apiReference, undefined)
  assert.equal(plan.openApi, null)
  assert.equal(plan.loginPath, null)
  assert.equal(plan.capabilityTier, 3)
})

test('mapping: grey-box exposes all personas plus an OpenAPI project spec', () => {
  const b = briefing('grey-box')
  const plan = planCell(b, pickLoginPath(b))
  assert.equal(plan.personas.length, 4)
  assert.equal(plan.loginPath, '/api/auth/login')
  assert.ok(plan.openApi)
  const doc = briefingToOpenApi(b)
  assert.equal(doc.openapi, '3.1.0')
  assert.ok(doc.paths['/api/invoices/:invoiceId']?.get)
  assert.deepEqual(doc.paths['/api/invoices/:invoiceId']?.get.parameters, [
    { name: 'invoiceId', in: 'path', required: true },
  ])
  assert.equal(plan.capabilityTier, 3)
})

test('mapping: white-box adds the source mount and Tier 3', () => {
  const b = briefing('white-box')
  const plan = planCell(b, pickLoginPath(b))
  assert.equal(plan.capabilityTier, 3)
  assert.equal(plan.briefing.sourceDir, '/tmp/realistic-bench/acme/src')
})

test('mapping: refuses inconsistent briefings (leaks or missing context)', () => {
  const leaked = { ...briefing('black-box'), apiReference: briefing('grey-box').apiReference }
  assert.throws(() => planCell(leaked, null), /black-box briefings must not include an API reference/)
  const grey = { ...briefing('grey-box') }
  delete (grey as { apiReference?: unknown }).apiReference
  assert.throws(() => planCell(grey, null), /grey-box briefings require an API reference/)
  const white = { ...briefing('white-box') }
  delete (white as { sourceDir?: unknown }).sourceDir
  assert.throws(() => planCell(white, '/login'), /white-box briefings require a source directory/)
  const tooMany: Briefing = {
    ...briefing('black-box'),
    personas: [
      ...briefing('black-box').personas,
      { id: 'admin', email: 'x@example.test', password: 'p', tenant: 't', role: 'admin' },
    ],
  }
  assert.throws(() => planCell(tooMany, null), /at most persona_a and persona_b/)
})

test('mapping: login route preference avoids legacy surfaces', () => {
  const b = briefing('grey-box')
  b.apiReference = [
    { routeKey: 'legacyLogin', method: 'POST', path: '/api/v1/login', params: [] },
    { routeKey: 'login', method: 'POST', path: '/api/auth/login', params: [] },
  ]
  assert.equal(pickLoginPath(b), '/api/auth/login')
})

// ---------------------------------------------------------------------------------------------
// Finding translation (persisted Kovo Hunter rows -> grader schema)
// ---------------------------------------------------------------------------------------------

function finding(overrides: Partial<Finding> & { id: string }): Finding {
  return {
    origin: 'http://127.0.0.1:4000',
    title: 'Cross-tenant invoice read',
    status: 'confirmed',
    severity: 'high',
    reason: 'Replay confirmed it.',
    remediation: 'Enforce ownership.',
    evidenceIds: [],
    scopeRevision: 1,
    cwe: 'CWE-639',
    findingKind: 'multi_step_chain',
    ...overrides,
  } as Finding
}

const httpChainSpec = {
  kind: 'http_chain',
  steps: [
    {
      id: 'c1', role: 'control',
      request: { origin: 'http://127.0.0.1:4000', method: 'GET', pathAndQuery: '/api/invoices/1001', followRedirects: false },
    },
    {
      id: 'p1', role: 'probe',
      request: {
        origin: 'http://127.0.0.1:4000', method: 'GET',
        pathAndQuery: '/api/invoices/2002?invoiceId=2002&expand=lines', followRedirects: false,
      },
    },
  ],
}

test('translation: confirmed/static/pending map to grader statuses and preserve evidence', () => {
  const specs = [
    { id: 's1', findingId: 'f-confirmed', spec: httpChainSpec, createdAt: 1000 },
    {
      id: 's2', findingId: 'f-static',
      spec: { kind: 'static_ast_proof', repo: 'bench/app', file: 'billing/invoices.ts', startLine: 10, endLine: 20, engine: 'opengrep', ruleOrPattern: 'x', runtimeProofGap: 'no runtime proof' },
      createdAt: 2000,
    },
    { id: 's3', findingId: 'f-pending', spec: httpChainSpec, createdAt: 3000 },
  ]
  const findings = [
    finding({ id: 'f-confirmed' }),
    finding({ id: 'f-static', status: 'static_verified', severity: 'medium' }),
    finding({ id: 'f-pending', status: 'pending' }),
    finding({ id: 'f-dismissed', status: 'dismissed' }),
    finding({ id: 'f-baseline', findingKind: 'baseline_check', status: 'inconclusive', severity: 'informational' }),
  ]
  const out = translateFindings({
    findings,
    replaySpecs: specs,
    endpoints: [{ id: 'e1', method: 'GET', pathTemplate: '/api/invoices/:invoiceId' }],
    endpointParams: [{ endpointId: 'e1', name: 'invoiceId' }],
    spentUsd: 1.25,
    secrets: [{ value: 'pw-a', placeholder: '[[pw]]' }],
  })
  assert.equal(out.length, 3)
  const confirmed = out.find(f => f.id === 'f-confirmed')!
  assert.equal(confirmed.status, 'runtime_confirmed')
  assert.equal(confirmed.cwe, 'CWE-639')
  assert.equal(confirmed.severity, 'high')
  assert.equal(confirmed.submittedAtMs, 1000)
  assert.equal(confirmed.costUsdAtSubmit, 1.25)
  assert.deepEqual(confirmed.endpoints, [
    { method: 'GET', path: '/api/invoices/1001' },
    { method: 'GET', path: '/api/invoices/2002?invoiceId=2002&expand=lines' },
  ])
  assert.deepEqual(confirmed.params, ['invoiceId'])
  const staticFinding = out.find(f => f.id === 'f-static')!
  assert.equal(staticFinding.status, 'static_verified')
  assert.equal(staticFinding.severity, 'medium')
  assert.deepEqual(staticFinding.endpoints, [])
  const pending = out.find(f => f.id === 'f-pending')!
  assert.equal(pending.status, 'proposed')
  assert.equal(pending.submittedAtMs, 3000)
  assert.ok(!out.some(f => f.id === 'f-dismissed' || f.id === 'f-baseline'))
})

test('translation: exchange fallback and redaction when no replay spec survived', () => {
  const out = translateFindings({
    findings: [finding({ id: 'f1', title: 'token=secret-value leaked', exchangeIds: ['x1'] })],
    replaySpecs: [],
    exchanges: [{ id: 'x1', method: 'POST', pathAndQuery: '/api/exports' }],
    secrets: [{ value: 'secret-value', placeholder: '[[secret]]' }],
    now: 9999,
  })
  assert.equal(out[0]?.submittedAtMs, 9999)
  assert.deepEqual(out[0]?.endpoints, [{ method: 'POST', path: '/api/exports' }])
  assert.doesNotMatch(out[0]?.title ?? '', /secret-value/)
})

test('translation: replay-spec endpoint extraction handles chain and cache shapes', () => {
  assert.deepEqual(endpointsFromReplaySpec(httpChainSpec), [
    { method: 'GET', path: '/api/invoices/1001' },
    { method: 'GET', path: '/api/invoices/2002?invoiceId=2002&expand=lines' },
  ])
  assert.deepEqual(endpointsFromReplaySpec({
    kind: 'cache_differential', method: 'GET',
    controlPath: '/item/1?_gcb=aaaaaaaaaaaaaaaa', probePath: '/item/2?_gcb=bbbbbbbbbbbbbbbb',
  }), [
    { method: 'GET', path: '/item/1?_gcb=aaaaaaaaaaaaaaaa' },
    { method: 'GET', path: '/item/2?_gcb=bbbbbbbbbbbbbbbb' },
  ])
})

test('translation: black-box credential probe refuses hostile origins quickly', async () => {
  // No listener at the port: every candidate fails fast and the helper returns null.
  const path = await probeLoginPath('http://127.0.0.1:9', [
    { id: 'persona_a', email: 'a@example.test', password: 'pw', tenant: 't', role: 'member' },
  ])
  assert.equal(path, null)
})

test('mapping: black-box login discovery accepts a conventional session route', async () => {
  const server = createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/login') {
      res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'bench_sid=abc; Path=/; HttpOnly' })
      res.end(JSON.stringify({ ok: true }))
      return
    }
    res.writeHead(404, { 'content-type': 'application/json' })
    res.end('{"error":"not_found"}')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  try {
    const address = server.address()
    assert.ok(address && typeof address !== 'string')
    const path = await probeLoginPath(`http://127.0.0.1:${address.port}`, [
      { id: 'persona_a', email: 'a@example.test', password: 'pw', tenant: 't', role: 'member' },
    ])
    assert.equal(path, '/login')
  } finally {
    server.closeAllConnections?.()
    await new Promise<void>(resolve => server.close(() => resolve()))
  }
})

// ---------------------------------------------------------------------------------------------
// Grading integration (no Execution boot)
// ---------------------------------------------------------------------------------------------

function integrationGroundTruth(): GroundTruth {
  return {
    schemaVersion: 1,
    app: 'acme-saas',
    seed: 1,
    seedSet: 'dev',
    vulns: [{
      siteId: 'acme.invoice-bola',
      title: 'Cross-tenant invoice read',
      vulnClass: 'bola',
      cwe: 'CWE-639',
      severity: 'high',
      endpoints: [{ method: 'GET', path: '/api/invoices/:invoiceId', routeKey: 'getInvoice' }],
      triggerEndpoints: [{ method: 'GET', path: '/api/invoices/:invoiceId', routeKey: 'getInvoice' }],
      params: ['invoiceId'],
      oracle: { kinds: ['cross_tenant_read'], routeKeys: ['getInvoice'] },
      rootCause: { file: 'billing/invoices.ts', symbol: 'getInvoice' },
    }],
    decoys: [{
      siteId: 'acme.decoy-idor',
      title: 'Hardened invoice lookup',
      vulnClass: 'idor',
      cwe: 'CWE-639',
      severity: 'medium',
      endpoints: [{ method: 'GET', path: '/api/orders/:orderId', routeKey: 'getOrder' }],
      triggerEndpoints: [],
      params: ['orderId'],
      oracle: { kinds: ['cross_tenant_read'], routeKeys: ['getOrder'] },
      rootCause: { file: 'orders/orders.ts', symbol: 'getOrder' },
    }],
    chains: [],
  }
}

test('grading: translated confirmed finding + attributed oracle event scores a TP', () => {
  const gt = integrationGroundTruth()
  const translated = translateFindings({
    findings: [
      finding({ id: 'f-confirmed' }),
      finding({ id: 'f-decoy', title: 'Order idor', cwe: 'CWE-639', status: 'pending' }),
    ],
    replaySpecs: [
      { id: 's1', findingId: 'f-confirmed', spec: httpChainSpec, createdAt: 1_000 },
      {
        id: 's2', findingId: 'f-decoy', createdAt: 1_100,
        spec: { kind: 'http_chain', steps: [
          { role: 'control', request: { method: 'GET', pathAndQuery: '/api/orders/1' } },
          { role: 'probe', request: { method: 'GET', pathAndQuery: '/api/orders/2' } },
        ] },
      },
    ],
    endpoints: [
      { id: 'e1', method: 'GET', pathTemplate: '/api/invoices/:invoiceId' },
      { id: 'e2', method: 'GET', pathTemplate: '/api/orders/:orderId' },
    ],
    endpointParams: [{ endpointId: 'e1', name: 'invoiceId' }, { endpointId: 'e2', name: 'orderId' }],
    spentUsd: 0.4,
  })
  const oracleEvents: OracleEvent[] = [
    {
      seq: 1, ts: 900, kind: 'cross_tenant_read', app: 'acme-saas',
      routeKey: 'getInvoice', method: 'GET', path: '/api/invoices/2002',
      actor: 'persona_a', detail: {},
    },
    {
      seq: 2, ts: 950, kind: 'cross_tenant_read', app: 'acme-saas',
      routeKey: 'getOrder', method: 'GET', path: '/api/orders/2',
      actor: 'persona_a', detail: {},
    },
  ]
  const requestLog: RequestLogEntry[] = [
    { seq: 1, ts: 800, method: 'GET', path: '/api/invoices/1001', routeKey: 'getInvoice', status: 200, actor: 'persona_a', paramNames: ['invoiceId'], suspicious: true },
    { seq: 2, ts: 850, method: 'GET', path: '/api/orders/1', routeKey: 'getOrder', status: 200, actor: 'persona_a', paramNames: ['orderId'], suspicious: true },
  ]
  const card: Scorecard = gradeRun({
    groundTruth: gt,
    findings: translated,
    oracleEvents,
    requestLog,
    telemetry: buildTelemetry({
      runStartedAt: 1, runEndedAt: 2, spentUsd: 0.4, budgetUsd: 5, budgetExhausted: false,
    }),
    mode: 'grey-box',
  })
  assert.equal(card.targets, 1)
  assert.equal(card.confirmed, 1)
  assert.equal(card.recall, 1)
  assert.equal(card.decoys, 1)
  assert.equal(card.decoyFalsePositives, 1)
  assert.equal(card.unmatchedFalsePositives, 0)
  assert.equal(card.funnel.zeroLlmConfirmed, 1)
  assert.equal(card.funnel.signalObserved, 1)
  assert.equal(card.chainsTotal, 0)
  assert.equal(card.totalCostUsd, 0.4)
  assert.equal(card.vulns[0]?.outcome, 'confirmed')
})

test('grading: a claimed finding without oracle impact is not a TP', () => {
  const translated = translateFindings({
    findings: [finding({ id: 'f-claim' })],
    replaySpecs: [{ id: 's1', findingId: 'f-claim', spec: httpChainSpec, createdAt: 1 }],
  })
  const card = gradeRun({
    groundTruth: integrationGroundTruth(),
    findings: translated,
    oracleEvents: [],
    requestLog: [],
    telemetry: buildTelemetry({ runStartedAt: 1, runEndedAt: 2, spentUsd: 0, budgetUsd: 5, budgetExhausted: false }),
    mode: 'grey-box',
  })
  assert.equal(card.confirmed, 0)
  assert.equal(card.vulns[0]?.outcome, 'claimed_without_impact')
  assert.equal(card.unmatchedFalsePositives, 0)
})

// ---------------------------------------------------------------------------------------------
// Model mode + shutdown
// ---------------------------------------------------------------------------------------------

test('model mode: an empty profile set is reported as deterministic, never simulated', () => {
  assert.deepEqual(describeModelMode([]), { mode: 'deterministic-no-llm', profiles: [] })
  const info = describeModelMode([
    { name: 'primary', model: 'vendor/model', protocol: 'responses' } as never,
  ])
  assert.equal(info.mode, 'agentic')
  assert.deepEqual(info.profiles, [{ name: 'primary', model: 'vendor/model', protocol: 'responses' }])
})

// ---------------------------------------------------------------------------------------------
// Agentic preflight / inert-run guard
// ---------------------------------------------------------------------------------------------

function preflight(overrides: Partial<Parameters<typeof assertAgenticPreflight>[0]> = {}) {
  return assertAgenticPreflight({
    hasProfiles: true,
    noLlm: false,
    allowInertWorkers: false,
    backendKind: 'local-jq',
    workerSessions: false,
    workerSessionsDetail: 'LocalJqBackend does not support worker sessions.',
    ...overrides,
  })
}

test('preflight: model profile + local-jq fails fast with exit code 2', () => {
  let caught: unknown
  try { preflight() } catch (error) { caught = error }
  assert.ok(caught instanceof PreflightError)
  assert.equal((caught as PreflightError).exitCode, 2)
  assert.match((caught as Error).message, /worker-session-capable verifier backend \(docker\)/)
  assert.match((caught as Error).message, /use --verifier docker or --no-llm/)
  assert.match((caught as Error).message, /LocalJqBackend does not support worker sessions/)
})

test('preflight: --no-llm + local-jq is allowed (deterministic path)', () => {
  assert.doesNotThrow(() => preflight({ noLlm: true }))
})

test('preflight: --allow-inert-workers is the explicit override', () => {
  assert.doesNotThrow(() => preflight({ allowInertWorkers: true }))
})

test('preflight: docker + model profile is allowed when a session really opens', () => {
  assert.doesNotThrow(() => preflight({ backendKind: 'docker', workerSessions: true, workerSessionsDetail: 'ok' }))
})

test('preflight: docker without socket access points at newgrp docker', () => {
  let caught: unknown
  try {
    preflight({ backendKind: 'docker', workerSessionsDetail: 'permission denied while trying to connect to the Docker daemon socket' })
  } catch (error) { caught = error }
  assert.ok(caught instanceof PreflightError)
  assert.equal((caught as PreflightError).exitCode, 2)
  assert.match((caught as Error).message, /newgrp docker -c/)
})

test('capability: worker sessions are probed by opening and closing a session', async () => {
  let closed = 0
  const capable = await detectWorkerSessions({
    openSession: async () => ({
      stage: async () => '', exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
      analyze: async () => ({}), sast: async () => ({} as never), runScript: async () => ({} as never),
      verifyStaticAst: async () => ({} as never), close: async () => { closed += 1 },
    }) as never,
  })
  assert.equal(capable.supported, true)
  assert.equal(closed, 1)

  const incapable = await detectWorkerSessions({
    openSession: async () => { throw new Error('LocalJqBackend does not support worker sessions.') },
  })
  assert.equal(incapable.supported, false)
  assert.match(incapable.detail, /does not support worker sessions/)
})

test('diagnostics: assignment totals, investigation counters and top reasons are recorded', () => {  const summary = summarizeAssignments([
    { status: 'complete', phase: 'threat_model' },
    { status: 'complete', phase: 'verification' },
    { status: 'complete', phase: 'investigation' },
    { status: 'failed', phase: 'investigation', outcome: 'LocalJqBackend does not support worker sessions.' },
    { status: 'failed', phase: 'investigation', outcome: 'LocalJqBackend does not support worker sessions.' },
    { status: 'failed', phase: 'investigation', outcome: 'broker denied: password=super-secret' },
    { status: 'canceled', phase: 'investigation', outcome: 'run stopped' },
  ], ['fallback reason should not be used'], [{ value: 'super-secret', placeholder: '[[secret]]' }])
  assert.equal(summary.total, 7)
  assert.equal(summary.completed, 3)
  assert.equal(summary.failed, 3)
  assert.equal(summary.canceled, 1)
  assert.equal(summary.investigationTotal, 5)
  assert.equal(summary.investigationCompleted, 1)
  assert.equal(summary.investigationFailed, 4)
  assert.equal(summary.topFailureReasons[0], 'LocalJqBackend does not support worker sessions.')
  assert.ok(summary.topFailureReasons.some(reason => reason.includes('broker denied')))
  assert.ok(!summary.topFailureReasons.some(reason => reason.includes('super-secret')))
  assert.ok(!summary.topFailureReasons.includes('fallback reason should not be used'))
})

test('inert detection: agentic runs with no completed investigation are never results', () => {
  assert.equal(isInertAgenticRun({ agentic: true, submittedFindings: 0, facts: 0, investigationCompleted: 0 }), true)
  assert.equal(isInertAgenticRun({ agentic: true, submittedFindings: 0, facts: 12, investigationCompleted: 0 }), false)
  assert.equal(isInertAgenticRun({ agentic: true, submittedFindings: 1, facts: 0, investigationCompleted: 0 }), false)
  assert.equal(isInertAgenticRun({ agentic: true, submittedFindings: 0, facts: 0, investigationCompleted: 2 }), false)
  assert.equal(isInertAgenticRun({ agentic: false, submittedFindings: 0, facts: 0, investigationCompleted: 0 }), false)
})

// ---------------------------------------------------------------------------------------------
// Per-cell data-dir isolation (parallel agentic matrix)
// ---------------------------------------------------------------------------------------------

const KEY_CANARY = 'sk-or-v1-LEAKCANARY0123456789abcdef'

test('isolation: defaults on for parallel cells with a source data dir', () => {
  const base = parseRealisticArgs(['--data-dir', '/tmp/source'], {})
  assert.equal(shouldIsolateDataDir(base), false)
  assert.equal(shouldIsolateDataDir({ ...base, concurrency: 3 }), true)
  assert.equal(shouldIsolateDataDir({ ...base, isolateDataDir: true }), true)
  assert.equal(shouldIsolateDataDir({ ...base, concurrency: 3, noLlm: true }), false)
  assert.equal(shouldIsolateDataDir({ ...base, dataDir: undefined, concurrency: 3 }), false)
})
function makeSourceDataDir(): { dir: string; credentialId: string; workspaceId: string; keep: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-iso-source-'))
  const storage = new Store(dir)
  const credentialId = randomUUID()
  const workspaceId = storage.workspace.id
  mkdirSync(join(dir, 'credentials'), { recursive: true, mode: 0o700 })
  writeFileSync(join(dir, 'credentials', credentialId), KEY_CANARY, { mode: 0o600 })
  storage.client.prepare(
    'insert into model_profiles (id, workspace_id, name, endpoint, model, protocol, credential_id, priority, '
    + 'enabled, context_window, max_tokens, thinking_level, role_affinity, input_cost_per_mtok, '
    + 'cached_input_cost_per_mtok, output_cost_per_mtok, health_state, cooldown_until, last_error, updated_at) '
    + 'values (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, null, null, ?)',
  ).run(
    randomUUID(), storage.workspace.id, 'Isolated Test Profile', 'https://openrouter.ai/api/v1',
    'test/isolated-model', 'responses', credentialId, 100, 128_000, 4_096, 'off', 'any', 0, 0, 0, 'closed', Date.now(),
  )
  storage.close()
  return { dir, credentialId, workspaceId, keep: () => rmSync(dir, { recursive: true, force: true }) }
}

function walkFilesNoFollow(dir: string): string[] {
  const files: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) continue
    const path = join(dir, entry.name)
    if (entry.isDirectory()) files.push(...walkFilesNoFollow(path))
    else if (entry.isFile()) files.push(path)
  }
  return files
}

test('isolation: two cell Stores run concurrently, profile visible, credentials symlinked, no key in out-dir', async () => {  const source = makeSourceDataDir()
  const outDir = mkdtempSync(join(tmpdir(), 'kovo-iso-out-'))
  try {
    const targetA = join(outDir, 'data', 'acme-saas-seed1-grey-box')
    const targetB = join(outDir, 'data', 'shopflow-seed1-grey-box')
    const [a, b] = await Promise.all([
      Promise.resolve().then(() => prepareIsolatedDataDir({ sourceDataDir: source.dir, targetDir: targetA })),
      Promise.resolve().then(() => prepareIsolatedDataDir({ sourceDataDir: source.dir, targetDir: targetB })),
    ])
    assert.deepEqual(a.profileNames, ['Isolated Test Profile'])
    assert.deepEqual(b.profileNames, ['Isolated Test Profile'])
    assert.notEqual(a.directory, b.directory)

    // Both Stores open at the same time: no "Another Kovo Hunter server" collision.
    const storeA = openCellStore(a.directory)
    const storeB = openCellStore(b.directory)
    try {
      assert.equal(privateModelProfiles(storeA).length, 1)
      assert.equal(privateModelProfiles(storeB).length, 1)
      assert.equal(privateModelProfiles(storeA)[0]?.name, 'Isolated Test Profile')
      assert.equal(privateModelProfiles(storeB)[0]?.name, 'Isolated Test Profile')
      assert.equal(storeA.workspace.id, source.workspaceId)
      assert.equal(storeB.workspace.id, source.workspaceId)

      for (const target of [targetA, targetB]) {
        const link = join(target, 'credentials')
        assert.ok(lstatSync(link).isSymbolicLink(), 'credentials must be a symlink')
        const resolved = readlinkSync(link)
        assert.equal(statSync(resolved).isDirectory(), true)
        assert.equal(statSync(join(link, source.credentialId)).mode & 0o777, 0o600)
      }
    } finally {
      storeA.close()
      storeB.close()
    }

    // No key material in regular files under the isolated out-dir (symlinks are skipped).
    const leaked = walkFilesNoFollow(outDir)
      .filter(file => readFileSync(file, 'utf8').includes(KEY_CANARY))
    assert.deepEqual(leaked, [])
    const credentialLinks = walkFilesNoFollow(outDir)
    assert.ok(!credentialLinks.includes(join(targetA, 'credentials', source.credentialId)))
  } finally {
    source.keep()
    rmSync(outDir, { recursive: true, force: true })
  }
})

test('isolation: a locked data dir suggests --isolate-data-dir with exit code 2', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-iso-lock-'))
  const first = new Store(dir)
  try {
    let caught: unknown
    try { openCellStore(dir) } catch (error) { caught = error }
    assert.ok(caught instanceof PreflightError)
    assert.equal((caught as PreflightError).exitCode, 2)
    assert.match((caught as Error).message, /--isolate-data-dir/)
  } finally {
    first.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

test('isolation: missing source profile fails before creating a run', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-iso-empty-'))
  const outDir = mkdtempSync(join(tmpdir(), 'kovo-iso-empty-out-'))
  try {
    const storage = new Store(dir)
    storage.close()
    assert.throws(
      () => prepareIsolatedDataDir({ sourceDataDir: dir, targetDir: join(outDir, 'data', 'cell') }),
      /no enabled model profile/,
    )
    assert.equal(existsSync(join(outDir, 'data', 'cell')), false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
    rmSync(outDir, { recursive: true, force: true })
  }
})

test('shutdown: stopEngine aborts promptly and reports zero busy tasks', async () => {
  let stopped = 0
  const fake = {
    stop: async () => { stopped += 1 },
    active: new Map(), coordinator: new Map(), threatModeling: new Map(),
    plannerTasks: new Map(), runAuthInFlight: new Map(),
  }
  const busy = await stopEngine(fake as never)
  assert.equal(stopped, 1)
  assert.equal(busy, 0)
})

test('smoke: a single-cell CLI run against a fake data dir refuses without local-lab consent', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m0-test-'))
  try {
    const result = await execFileAsync(process.execPath, [
      'scripts/benchmark-realistic.ts', '--app', 'acme-saas', '--seed', '1',
      '--mode', 'grey-box', '--out-dir', dir,
    ], {
      cwd: repoRoot,
      env: { ...process.env, KOVO_ALLOW_LOCAL_LAB: '' },
    }).then(() => ({ code: 0, stderr: '' }), (error: { code?: number; stderr?: string }) => ({
      code: error.code ?? 1, stderr: String(error.stderr ?? ''),
    }))
    assert.notEqual(result.code, 0)
    assert.match(result.stderr, /KOVO_ALLOW_LOCAL_LAB/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
