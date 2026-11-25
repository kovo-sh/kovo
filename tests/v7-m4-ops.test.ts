import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createGuardianLocalServer } from '../scripts/serve.ts'
import { purgeExpiredArtifacts } from '../src/server/artifact-ttl.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant, Transport } from '../src/server/broker.ts'
import { buildCoverageGapReport, formatCoverageGapMarkdown } from '../src/server/coverage-gaps.ts'
import { GlobalKillSwitch, KillSwitchTrippedError } from '../src/server/kill-switch.ts'
import { exportRunReceiptBundle, verifyProofReceiptBundle } from '../src/server/receipt-export.ts'
import { redactPii, redactZdr, redactZdrJsonValue } from '../src/server/redact.ts'
import { exportReportMarkdown } from '../src/server/report-export.ts'
import {
  brokerExchanges,
  endpoints,
  evidence,
  findings as findingsTable,
  replaySpecs,
  reports,
  retestRuns,
} from '../src/server/schema.ts'
import {
  evaluateSignedScopeRequest,
  signScopeManifest,
  verifyScopeManifest,
} from '../src/server/scope-policy.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'
import { Store, TenantIsolationError } from '../src/server/store.ts'

const appOrigin = 'https://target.example.test'

function tempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), `guardian-${prefix}-`))
}

function makeGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    origin: appOrigin,
    tier: 2,
    maxRpsPerOrigin: 50,
    canRead: o => o === appOrigin,
    audit: () => {},
    ...overrides,
  }
}

function makeRunSetup(storage: Store, name = 'M4 Ops Project') {
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name,
    seeds: [appOrigin],
    environment: 'public',
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId,
    goal: 'Production ops verification',
    sourceMode: 'public',
    capabilityTier: 2,
    budgetUsd: 10,
    budgetRequests: 50,
    maxRpsPerOrigin: 5,
    workerConcurrency: 1,
    workerMaxTurns: 5,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const asset = storage.run(runId).candidates[0]!
  storage.command({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    expectedScopeRevision: 0,
    assetIds: [asset.id],
    consent: true,
    capabilityTier: 2,
  })
  const worker = storage.makeWorker(storage.run(runId), 'investigation', asset, 'Probe', 'M4 ops check')
  return { projectId, runId, asset, worker }
}

// ============================================================================
// 1. Signed Scope Manifest (HMAC-SHA256 & Ed25519) + Tamper Rejection
// ============================================================================

test('M4: signed scope manifest verifies HMAC-SHA256 & Ed25519 and rejects tampered/expired/cross-tenant manifests', () => {
  const policy: ScopePolicy = {
    mode: 'prod_readonly',
    targetOrigins: [appOrigin],
    authOrigins: ['https://auth.example.test'],
    assetOrigins: ['https://cdn.example.test'],
  }
  const now = 1_760_000_000_000
  const hmacSecret = 'm4-scope-signing-secret-0123456789abcdef'
  const payload = {
    version: 1 as const,
    manifestId: 'manifest-m4-001',
    tenantId: 'tenant-alpha',
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 300_000).toISOString(),
    policy,
  }

  // HMAC-SHA256 happy path
  const signedHmac = signScopeManifest(payload, {
    algorithm: 'hmac-sha256',
    secret: hmacSecret,
    keyId: 'ops-hmac-1',
  })
  const verifiedHmac = verifyScopeManifest(signedHmac, {
    algorithm: 'hmac-sha256',
    secret: hmacSecret,
    expectedTenantId: 'tenant-alpha',
    now: now + 60_000,
  })
  assert.equal(verifiedHmac.valid, true)
  if (verifiedHmac.valid) {
    assert.equal(verifiedHmac.payload.tenantId, 'tenant-alpha')
  }

  // Tampered payload rejected
  const tamperedPayload = {
    ...signedHmac,
    payload: {
      ...signedHmac.payload,
      policy: { ...policy, mode: 'staging_isolated' as const },
    },
  }
  const resTampered = verifyScopeManifest(tamperedPayload, { secret: hmacSecret, now: now + 1000 })
  assert.equal(resTampered.valid, false)
  if (!resTampered.valid) assert.match(resTampered.reason, /HMAC signature/i)

  // Expired manifest rejected
  const resExpired = verifyScopeManifest(signedHmac, { secret: hmacSecret, now: now + 400_000 })
  assert.equal(resExpired.valid, false)
  if (!resExpired.valid) assert.match(resExpired.reason, /expired/i)

  // Tenant mismatch rejected
  const resWrongTenant = verifyScopeManifest(signedHmac, {
    secret: hmacSecret,
    expectedTenantId: 'tenant-beta',
    now: now + 1000,
  })
  assert.equal(resWrongTenant.valid, false)
  if (!resWrongTenant.valid) assert.match(resWrongTenant.reason, /tenant/i)

  // evaluateSignedScopeRequest fails closed on tampered manifest
  const deniedDecision = evaluateSignedScopeRequest(
    tamperedPayload,
    { secret: hmacSecret, now: now + 1000 },
    { origin: appOrigin, method: 'GET', pathAndQuery: '/api/health' },
  )
  assert.equal(deniedDecision.allowed, false)
  assert.equal(deniedDecision.code, 'invalid_scope_manifest')

  // evaluateSignedScopeRequest enforces prod_readonly on valid manifest
  const allowedGet = evaluateSignedScopeRequest(
    signedHmac,
    { secret: hmacSecret, expectedTenantId: 'tenant-alpha', now: now + 1000 },
    { origin: appOrigin, method: 'GET', pathAndQuery: '/api/health' },
  )
  assert.equal(allowedGet.allowed, true)
  const blockedPost = evaluateSignedScopeRequest(
    signedHmac,
    { secret: hmacSecret, expectedTenantId: 'tenant-alpha', now: now + 1000 },
    { origin: appOrigin, method: 'POST', pathAndQuery: '/api/orders', body: '{"qty":1}' },
  )
  assert.equal(blockedPost.allowed, false)
  assert.equal(blockedPost.code, 'readonly_environment')

  // Ed25519 sign + verify + wrong public key rejection
  const pair1 = generateKeyPairSync('ed25519')
  const pair2 = generateKeyPairSync('ed25519')
  const signedEd = signScopeManifest(payload, {
    algorithm: 'ed25519',
    privateKey: pair1.privateKey,
    keyId: 'ops-ed-1',
  })
  assert.equal(verifyScopeManifest(signedEd, { algorithm: 'ed25519', publicKey: pair1.publicKey, now: now + 1000 }).valid, true)
  assert.equal(verifyScopeManifest(signedEd, { algorithm: 'ed25519', publicKey: pair2.publicKey, now: now + 1000 }).valid, false)
})

// ============================================================================
// 2. < 2s Global Kill Switch Chaos Test (Concurrent In-Flight + Zero Post-Trip)
// ============================================================================

test('M4 chaos: global kill switch aborts 8 concurrent in-flight broker requests in < 2s with zero requests after trip', async t => {
  const dir = tempDir('m4-ks')
  const ksFile = join(dir, 'kill-switch.json')
  try {
    const ks = new GlobalKillSwitch({ filePath: ksFile, pollIntervalMs: 5 })
    let transportCalls = 0
    let transportCallsAfterTrip = 0
    let tripped = false
    let inflightEntered = 0
    let allEnteredResolve!: () => void
    const allEntered = new Promise<void>(r => { allEnteredResolve = r })

    const slowTransport: Transport = (_url, _addr, signal) => {
      transportCalls += 1
      if (tripped) transportCallsAfterTrip += 1
      inflightEntered += 1
      // Per-origin broker concurrency cap is 2; the other 6 concurrent requests queue in acquireSlot.
      if (inflightEntered === 2) allEnteredResolve()
      return new Promise((resolve, reject) => {
        if (signal.aborted) {
          reject(signal.reason ?? new Error('aborted'))
          return
        }
        const timer = setTimeout(() => {
          resolve({ status: 200, headers: { 'content-type': 'text/plain' }, body: 'slow-ok' })
        }, 10_000)
        signal.addEventListener('abort', () => {
          clearTimeout(timer)
          reject(signal.reason ?? new Error('aborted'))
        }, { once: true })
      })
    }

    const broker = new RequestBroker({
      resolve: async () => [{ address: '93.184.216.34', family: 4 }],
      transport: slowTransport,
      killSwitch: ks,
    })
    const grant = makeGrant({ tenantId: 'tenant-chaos' })
    const caller = new AbortController()

    // Launch 8 concurrent slow requests (2 active in transport + 6 queued in acquireSlot)
    const inFlight = Array.from({ length: 8 }, (_, i) =>
      broker.executeHttp(
        { origin: appOrigin, method: 'GET', pathAndQuery: `/slow/${i}`, timeoutMs: 15_000 },
        grant,
        caller.signal,
      ),
    )

    await allEntered
    assert.equal(ks.activeControllerCount(), 8)
    const callsBeforeTrip = transportCalls

    // Trip kill switch mid-flight and measure abort latency
    const tripStart = performance.now()
    tripped = true
    ks.trip({ reason: 'Chaos drill: emergency stop', trippedBy: 'sre-oncall' })
    const settled = await Promise.allSettled(inFlight)
    const abortLatencyMs = performance.now() - tripStart
    t.diagnostic(`kill-switch abort latency (8 concurrent in-flight/queued): ${abortLatencyMs.toFixed(2)}ms`)

    assert.ok(abortLatencyMs < 2000, `Expected < 2000ms abort latency, got ${abortLatencyMs.toFixed(2)}ms`)
    assert.equal(settled.length, 8)
    for (const outcome of settled) {
      assert.equal(outcome.status, 'rejected')
      assert.ok(outcome.reason instanceof KillSwitchTrippedError, `Expected KillSwitchTrippedError, got ${String(outcome.reason)}`)
    }
    assert.equal(ks.activeControllerCount(), 0)
    // Backing file must be owner-only 0600
    assert.equal(statSync(ksFile).mode & 0o077, 0)

    // Fire 5 concurrent post-trip follow-up requests — ZERO may reach transport (nor any of the 6 queued!)
    const postTrip = await Promise.allSettled(
      Array.from({ length: 5 }, (_, i) =>
        broker.executeHttp(
          { origin: appOrigin, method: 'GET', pathAndQuery: `/after/${i}` },
          grant,
          caller.signal,
        ),
      ),
    )
    assert.equal(transportCalls, callsBeforeTrip)
    assert.equal(transportCallsAfterTrip, 0)
    for (const outcome of postTrip) {
      assert.equal(outcome.status, 'rejected')
      assert.ok(outcome.reason instanceof KillSwitchTrippedError)
    }

    // Sibling GlobalKillSwitch instance backed by the same file observes external trip immediately
    const siblingKs = new GlobalKillSwitch({ filePath: ksFile, pollIntervalMs: 0 })
    assert.equal(siblingKs.isActive('tenant-chaos'), true)
    assert.throws(() => siblingKs.assertAllowed('tenant-chaos'), KillSwitchTrippedError)

    // Reset restores traffic cleanly; tenant-scoped trip halts only Tenant A
    ks.reset({ resetBy: 'sre-oncall' })
    let okCalls = 0
    const fastBroker = new RequestBroker({
      resolve: async () => [{ address: '93.184.216.34', family: 4 }],
      transport: async () => {
        okCalls += 1
        return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }
      },
      killSwitch: ks,
    })
    ks.trip({ reason: 'Tenant A pause', trippedBy: 'sre-oncall', tenantId: 'tenant-a' })
    await assert.rejects(
      fastBroker.executeHttp({ origin: appOrigin, method: 'GET', pathAndQuery: '/a' }, makeGrant({ tenantId: 'tenant-a' }), caller.signal),
      KillSwitchTrippedError,
    )
    const tenantBRes = await fastBroker.executeHttp(
      { origin: appOrigin, method: 'GET', pathAndQuery: '/b' },
      makeGrant({ tenantId: 'tenant-b' }),
      caller.signal,
    )
    assert.equal(tenantBRes.status, 200)
    assert.equal(okCalls, 1)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

// ============================================================================
// 3. ZDR/PII Redaction + Deterministic Artifact TTL Purge
// ============================================================================

test('M4: ZDR/PII redaction scrubs emails, SSNs, Luhn cards, phones, tokens; TTL purge removes expired rows/files & skips symlinks', () => {
  const sample = [
    'Contact alice.smith@corp.example or +1 (415) 555-0192',
    'SSN: 123-45-6789',
    'Card: 4532-0151-1283-0366', // Luhn-valid test PAN
    'OrderId: 1234-5678-9012-3457', // Non-Luhn ID must NOT be over-redacted
    'Authorization: Bearer sk_live_superSecretTokenValue999999',
  ].join('\n')

  const scrubbed = redactPii(sample)
  assert.ok(!scrubbed.includes('alice.smith@corp.example'))
  assert.ok(!scrubbed.includes('123-45-6789'))
  assert.ok(!scrubbed.includes('4532-0151-1283-0366'))
  assert.ok(!scrubbed.includes('555-0192'))
  assert.ok(!scrubbed.includes('sk_live_superSecretTokenValue999999'))
  assert.ok(scrubbed.includes('[pii:email]'))
  assert.ok(scrubbed.includes('[pii:ssn]'))
  assert.ok(scrubbed.includes('[pii:card]'))
  assert.ok(scrubbed.includes('[pii:phone]'))
  assert.ok(scrubbed.includes('1234-5678-9012-3457'), 'Non-Luhn numeric ID should be preserved')

  const scrubbedJson = redactZdrJsonValue({
    user: { email: 'bob@example.org', note: 'Call 415-555-2671' },
    secret: 'sk_live_anotherSecretToken888888',
  }) as { user: { email: string; note: string }; secret: string }
  assert.equal(scrubbedJson.user.email, '[pii:redacted]')
  assert.ok(!scrubbedJson.user.note.includes('555-2671'))
  assert.ok(!scrubbedJson.secret.includes('anotherSecretToken888888'))
  assert.equal(redactZdr('bob@example.org'), '[pii:email]')

  // Deterministic TTL purge test
  const dir = tempDir('m4-ttl')
  const outsideSentinel = join(dir, 'outside-sentinel.txt')
  writeFileSync(outsideSentinel, 'DO_NOT_DELETE', 'utf8')
  const storage = new Store(join(dir, 'data'))
  try {
    const { runId, worker } = makeRunSetup(storage, 'TTL Purge Project')
    storage.setRunTenant(runId, 'tenant-ttl')
    // Mark run complete so default skipActiveRuns=true includes it
    storage.updateRun(runId, { status: 'complete' })

    const now = 1_760_000_000_000
    const oldTs = now - 3 * 60 * 60_000 // 3 hours ago
    const freshTs = now - 5 * 60_000 // 5 minutes ago

    // Seed aged & fresh exchanges (with body blobs)
    const oldEx = storage.recordExchange({
      runId,
      assignmentId: worker.id,
      scopeRevision: 1,
      origin: appOrigin,
      finalOrigin: appOrigin,
      redirectOrigins: [appOrigin],
      method: 'GET',
      pathAndQuery: '/aged',
      status: 200,
      mediaType: 'text/plain',
      reqHeaders: {},
      respHeaders: {},
      body: 'aged-response-body-unique-blob-1111',
      durationMs: 10,
    })
    const freshEx = storage.recordExchange({
      runId,
      assignmentId: worker.id,
      scopeRevision: 1,
      origin: appOrigin,
      finalOrigin: appOrigin,
      redirectOrigins: [appOrigin],
      method: 'GET',
      pathAndQuery: '/fresh',
      status: 200,
      mediaType: 'text/plain',
      reqHeaders: {},
      respHeaders: {},
      body: 'fresh-response-body-unique-blob-2222',
      durationMs: 10,
    })
    storage.flushNow()
    storage.client.prepare('UPDATE broker_exchanges SET created_at = ? WHERE id = ?').run(oldTs, oldEx.id)
    storage.client.prepare('UPDATE broker_exchanges SET created_at = ? WHERE id = ?').run(freshTs, freshEx.id)

    // Seed aged & fresh evidence rows + sharded disk files
    const agedEvId = `ev-aged-${randomUUID().slice(0, 8)}`
    const freshEvId = `ev-fresh-${randomUUID().slice(0, 8)}`
    storage.db.insert(evidence).values([
      {
        id: agedEvId,
        runId,
        assignmentId: worker.id,
        scopeRevision: 1,
        goalRevision: 0,
        title: 'Aged capture',
        kind: 'observation',
        operationId: null,
        createdAt: oldTs,
      },
      {
        id: freshEvId,
        runId,
        assignmentId: worker.id,
        scopeRevision: 1,
        goalRevision: 0,
        title: 'Fresh capture',
        kind: 'observation',
        operationId: null,
        createdAt: freshTs,
      },
    ]).run()

    const agedBucket = createHash('sha256').update(agedEvId).digest('hex').slice(0, 2)
    const freshBucket = createHash('sha256').update(freshEvId).digest('hex').slice(0, 2)
    const agedEvFile = join(storage.directory, 'artifacts', runId, agedBucket, `${agedEvId}.txt`)
    const freshEvFile = join(storage.directory, 'artifacts', runId, freshBucket, `${freshEvId}.txt`)
    mkdirSync(join(storage.directory, 'artifacts', runId, agedBucket), { recursive: true })
    mkdirSync(join(storage.directory, 'artifacts', runId, freshBucket), { recursive: true })
    writeFileSync(agedEvFile, 'aged artifact content', 'utf8')
    writeFileSync(freshEvFile, 'fresh artifact content', 'utf8')

    // Seed aged temp file, fresh temp file, and symlink trap inside `<data>/tmp`
    const tmpDir = join(storage.directory, 'tmp')
    mkdirSync(tmpDir, { recursive: true })
    const agedTmp = join(tmpDir, 'aged-scratch.tmp')
    const freshTmp = join(tmpDir, 'fresh-scratch.tmp')
    const symlinkTrap = join(tmpDir, 'trap-link.tmp')
    writeFileSync(agedTmp, 'old temp payload', 'utf8')
    writeFileSync(freshTmp, 'new temp payload', 'utf8')
    utimesSync(agedTmp, new Date(oldTs), new Date(oldTs))
    utimesSync(freshTmp, new Date(freshTs), new Date(freshTs))
    symlinkSync(outsideSentinel, symlinkTrap)

    const purged = purgeExpiredArtifacts(storage, {
      tenantId: 'tenant-ttl',
      exchangeTtlMs: 60 * 60_000,
      artifactTtlMs: 60 * 60_000,
      tempFileTtlMs: 60 * 60_000,
      now,
    })

    assert.equal(purged.runsScanned, 1)
    assert.equal(purged.exchangesDeleted, 1)
    assert.equal(purged.blobsDeleted, 1)
    assert.equal(purged.artifactsDeleted, 1)
    assert.equal(purged.artifactFilesDeleted, 1)
    assert.equal(purged.tempFilesDeleted, 1)
    assert.ok(purged.symlinksSkipped >= 1)

    // Verify aged items gone and fresh + sentinel preserved
    assert.equal(existsSync(agedEvFile), false)
    assert.equal(existsSync(freshEvFile), true)
    assert.equal(existsSync(agedTmp), false)
    assert.equal(existsSync(freshTmp), true)
    assert.equal(existsSync(outsideSentinel), true)
    assert.equal(readFileSync(outsideSentinel, 'utf8'), 'DO_NOT_DELETE')

    const remainingExchanges = storage.db.select().from(brokerExchanges).all()
    assert.deepEqual(remainingExchanges.map(e => e.id), [freshEx.id])

    const auditEntries = storage.listTenantAuditLog('tenant-ttl')
    assert.ok(auditEntries.some(e => e.action === 'artifact.ttl_purge' && e.outcome === 'purged'))
  } finally {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

// ============================================================================
// 4. Per-Tenant Isolation & Append-Only Hash-Chained Audit Log
// ============================================================================

test('M4: per-tenant isolation prevents cross-tenant visibility/access and enforces append-only audit log', () => {
  const dir = tempDir('m4-tenant')
  const storage = new Store(dir)
  try {
    const a = makeRunSetup(storage, 'Tenant A App')
    const b = makeRunSetup(storage, 'Tenant B App')
    storage.setProjectTenant(a.projectId, 'tenant-a')
    storage.setProjectTenant(b.projectId, 'tenant-b')

    assert.equal(storage.getRunTenant(a.runId), 'tenant-a')
    assert.equal(storage.getRunTenant(b.runId), 'tenant-b')
    assert.deepEqual(storage.listProjectsForTenant('tenant-a').map(p => p.id), [a.projectId])
    assert.deepEqual(storage.listProjectsForTenant('tenant-b').map(p => p.id), [b.projectId])
    assert.deepEqual(storage.listRunsForTenant('tenant-a').map(r => r.id), [a.runId])
    assert.deepEqual(storage.listRunsForTenant('tenant-b').map(r => r.id), [b.runId])

    // Same-tenant access succeeds
    storage.assertRunTenantAccess(a.runId, 'tenant-a')

    // Cross-tenant access throws TenantIsolationError and records denied audit entry
    assert.throws(
      () => storage.assertRunTenantAccess(a.runId, 'tenant-b', 'user:bob'),
      (err: unknown) => err instanceof TenantIsolationError && err.code === 'TENANT_ISOLATION_DENIED',
    )

    // PII inside audit log detail is automatically scrubbed
    const entry = storage.appendTenantAuditLog({
      tenantId: 'tenant-b',
      runId: b.runId,
      actor: 'user:bob',
      action: 'report.viewed',
      resourceKind: 'report',
      outcome: 'allowed',
      detail: { requesterEmail: 'bob@tenant-b.example', ssn: '987-65-4321' },
    })
    assert.equal(entry.detail.requesterEmail, '[pii:email]')
    assert.equal(entry.detail.ssn, '[pii:redacted]')

    // Hash chain verifies cleanly
    const chain = storage.verifyTenantAuditLogChain('tenant-b')
    assert.equal(chain.valid, true)
    assert.equal(chain.count, 2)

    // SQLite triggers enforce append-only immutability (UPDATE & DELETE must abort)
    assert.throws(
      () => storage.client.prepare("UPDATE tenant_audit_log SET outcome = 'allowed' WHERE seq = ?").run(entry.seq),
      /invariant\.audit_log_append_only/,
    )
    assert.throws(
      () => storage.client.prepare('DELETE FROM tenant_audit_log WHERE seq = ?').run(entry.seq),
      /invariant\.audit_log_append_only/,
    )
  } finally {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

// ============================================================================
// 5. Honest Coverage-Gap Reporting (All 5 Buckets, Zero Fabrication)
// ============================================================================

test('M4: honest coverage-gap report detects all 5 real gap categories with zero fabrication on clean runs', () => {
  const dir = tempDir('m4-gaps')
  const storage = new Store(dir)
  try {
    // Clean run: tested route, no errors -> 0 gaps fabricated
    const clean = makeRunSetup(storage, 'Clean Run')
    const cleanNow = Date.now()
    storage.db.insert(endpoints).values({
      id: randomUUID(),
      runId: clean.runId,
      scopeRevision: 1,
      origin: appOrigin,
      method: 'GET',
      pathTemplate: '/api/health',
      source: 'spa_crawl',
      createdAt: cleanNow,
      updatedAt: cleanNow,
    }).run()
    storage.recordExchange({
      runId: clean.runId,
      assignmentId: clean.worker.id,
      scopeRevision: 1,
      origin: appOrigin,
      finalOrigin: appOrigin,
      redirectOrigins: [appOrigin],
      method: 'GET',
      pathAndQuery: '/api/health',
      status: 200,
      mediaType: 'application/json',
      reqHeaders: {},
      respHeaders: {},
      body: '{"ok":true}',
      durationMs: 12,
    })
    storage.flushNow()
    const cleanReport = buildCoverageGapReport(storage, clean.runId)
    assert.equal(cleanReport.totalGaps, 0)
    assert.match(cleanReport.honestSummary, /No operational coverage gaps/i)

    // Gap-bearing run: seed all 5 real telemetry gap categories
    const gappy = makeRunSetup(storage, 'Gappy Run')
    storage.setRunTenant(gappy.runId, 'tenant-gaps')

    // 1. auth_failed: persona-bound 401
    storage.recordExchange({
      runId: gappy.runId,
      assignmentId: gappy.worker.id,
      scopeRevision: 1,
      origin: appOrigin,
      finalOrigin: appOrigin,
      redirectOrigins: [appOrigin],
      method: 'GET',
      pathAndQuery: '/api/account',
      personaHandle: 'standard_user',
      status: 401,
      mediaType: 'application/json',
      reqHeaders: {},
      respHeaders: {},
      body: '{"error":"unauthorized for alice@corp.example"}',
      durationMs: 15,
    })
    // 2. waf_blocked: 429 + Cloudflare 403
    storage.recordExchange({
      runId: gappy.runId,
      assignmentId: gappy.worker.id,
      scopeRevision: 1,
      origin: appOrigin,
      finalOrigin: appOrigin,
      redirectOrigins: [appOrigin],
      method: 'GET',
      pathAndQuery: '/api/search?q=test',
      status: 429,
      mediaType: 'text/html',
      reqHeaders: {},
      respHeaders: { 'cf-ray': '8a123456-SJC' },
      body: 'Rate limited by Cloudflare WAF',
      durationMs: 22,
    })
    // 3. prod_readonly_skipped event
    storage.event(gappy.runId, 'scope.denied', 'Mutation refused by prod_readonly environment policy.', {
      origin: appOrigin,
      code: 'readonly_environment',
    })
    // 4. oob_unreachable event
    storage.event(gappy.runId, 'oob.relay_failed', 'OOB canary relay unreachable from target network.', {
      origin: appOrigin,
    })
    // 5. uncovered_routes: discovered endpoint with zero exchanges
    const epNow = Date.now()
    storage.db.insert(endpoints).values({
      id: randomUUID(),
      runId: gappy.runId,
      scopeRevision: 1,
      origin: appOrigin,
      method: 'POST',
      pathTemplate: '/api/admin/export',
      source: 'openapi',
      createdAt: epNow,
      updatedAt: epNow,
    }).run()
    storage.flushNow()

    const gapReport = buildCoverageGapReport(storage, gappy.runId, { zdr: true })
    assert.equal(gapReport.countsByKind.auth_failed, 1)
    assert.equal(gapReport.countsByKind.waf_blocked, 1)
    assert.equal(gapReport.countsByKind.prod_readonly_skipped, 1)
    assert.equal(gapReport.countsByKind.oob_unreachable, 1)
    assert.equal(gapReport.countsByKind.uncovered_routes, 1)
    assert.equal(gapReport.totalGaps, 5)

    const mdSection = formatCoverageGapMarkdown(gapReport)
    assert.match(mdSection, /## Operational coverage gaps/)
    assert.match(mdSection, /`auth_failed`/)
    assert.match(mdSection, /`waf_blocked`/)
    assert.match(mdSection, /`prod_readonly_skipped`/)
    assert.match(mdSection, /`oob_unreachable`/)
    assert.match(mdSection, /`uncovered_routes`/)

    // Verify exportReportMarkdown embeds gaps and scrubs PII in ZDR mode
    const reportId = randomUUID()
    storage.db.insert(reports).values({
      id: reportId,
      runId: gappy.runId,
      version: 1,
      partial: false,
      body: {
        goal: 'Production ops verification for alice@corp.example with SSN 123-45-6789.',
        capabilityTier: 2,
        scope: [gappy.asset],
        scopeRevision: 1,
        goalRevision: 0,
        findings: [],
        coverage: [],
        gaps: [],
        nextSteps: ['Fix auth for alice@corp.example'],
      } as never,
      createdAt: Date.now(),
    }).run()

    const md = exportReportMarkdown(storage, gappy.runId, reportId, { zdr: true, tenantId: 'tenant-gaps' })
    assert.ok(!md.content.includes('alice@corp.example'))
    assert.ok(!md.content.includes('123-45-6789'))
    assert.match(md.content, /## Operational coverage gaps/)
  } finally {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

// ============================================================================
// 6. Portable ProofReceipt Export + Live HTTP Ops Endpoints (`scripts/serve.ts`)
// ============================================================================

test('M4: portable ProofReceipt export signs/verifies, enforces ZDR & tenant isolation, and live HTTP ops endpoints work end-to-end', async () => {
  const dir = tempDir('m4-export-http')
  const storage = new Store(join(dir, 'data'))
  const ks = new GlobalKillSwitch({ filePath: join(dir, 'ks.json'), pollIntervalMs: 5 })
  const { projectId, runId, asset, worker } = makeRunSetup(storage, 'Receipt Export App')
  storage.setRunTenant(runId, 'tenant-alpha')

  // Record an exchange containing PII + secret-like token
  const ex = storage.recordExchange({
    runId,
    assignmentId: worker.id,
    scopeRevision: 1,
    origin: appOrigin,
    finalOrigin: appOrigin,
    redirectOrigins: [appOrigin],
    method: 'GET',
    pathAndQuery: '/api/invoices/42?email=victim@corp.example',
    personaHandle: 'user_b',
    status: 200,
    mediaType: 'application/json',
    reqHeaders: { 'x-trace': 'trace-1', authorization: 'Bearer sk_live_shouldNeverLeak123456' },
    respHeaders: { 'content-type': 'application/json' },
    body: '{"invoiceId":42,"ownerEmail":"victim@corp.example","ssn":"123-45-6789"}',
    durationMs: 18,
  })
  storage.flushNow()

  const findingId = randomUUID()
  const specId = randomUUID()
  const now = Date.now()
  const proofReceiptRow = {
    receipt: {
      vulnClass: 'idor',
      target: { origin: appOrigin, method: 'GET', pathAndQuery: '/api/invoices/42?email=victim@corp.example' },
      exchangeIds: [ex.id],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: 'user_b read tenant_a invoice owned by victim@corp.example',
      resourceTenant: 'user_a',
      expectControlDenied: true,
    },
    verification: {
      confirmed: true,
      vulnClass: 'idor',
      rule: 'idor.cross_tenant_read',
      reason: 'Cross-tenant record returned 200 to user_b',
      observed: 'HTTP 200 with foreign invoice belonging to victim@corp.example',
      expected: 'HTTP 403/404 denied for user_b',
    },
  }

  storage.db.insert(replaySpecs).values({
    id: specId,
    runId,
    findingId,
    assignmentId: worker.id,
    scopeRevision: 1,
    goalRevision: 0,
    spec: {
      kind: 'idor',
      origin: appOrigin,
      pathAndQuery: '/api/invoices/42',
    } as never,
    specSha256: createHash('sha256').update(specId).digest('hex'),
    sourceOrigins: [appOrigin],
    lastVerificationDiff: { verdict: 'confirmed' } as never,
    proofKind: 'agent_script',
    proofVerdict: 'confirmed',
    proofRuntime: 'ts',
    proofScriptSha256: createHash('sha256').update('verify-script').digest('hex'),
    proofArtifactId: null,
    proofReceipt: proofReceiptRow,
    createdAt: now,
  }).run()

  storage.db.insert(findingsTable).values({
    id: findingId,
    runId,
    assetId: asset.id,
    goalRevision: 0,
    checkId: 'chain',
    caseId: 'idor-invoice-42',
    findingKind: 'multi_step_chain',
    replaySpecId: specId,
    provenance: 'floor',
    verificationClass: 'runtime_confirmed',
    sourceOrigins: [appOrigin],
    verificationTier: 'runtime_confirmed',
    fingerprintHash: createHash('sha256').update(`idor:${appOrigin}:/api/invoices/:id`).digest('hex'),
    finding: {
      id: findingId,
      title: 'Cross-tenant invoice exposure for victim@corp.example',
      severity: 'high',
      category: 'idor',
      cwe: 'CWE-639',
      origin: appOrigin,
      status: 'confirmed',
      reason: 'Cross-tenant invoice read confirmed via ProofReceipt',
      verification: 'ProofReceipt: idor.cross_tenant_read',
      exchangeIds: [ex.id],
      evidenceIds: [],
    } as never,
  }).run()

  storage.db.insert(retestRuns).values({
    id: randomUUID(),
    projectId,
    runId,
    findingId,
    replaySpecId: specId,
    scopeRevision: 1,
    verdict: 'fixed',
    summary: 'Post-patch retest returned HTTP 403 for victim@corp.example invoice.',
    evidenceIds: [],
    exchangeIds: [ex.id],
    createdAt: now + 1000,
  }).run()

  // 1. Direct export & Ed25519 signature verification + tamper rejection
  const edKeys = generateKeyPairSync('ed25519')
  const edBundle = exportRunReceiptBundle(storage, runId, {
    tenantId: 'tenant-alpha',
    zdr: true,
    signing: { algorithm: 'ed25519', privateKey: edKeys.privateKey, keyId: 'receipt-ed-1' },
    now,
  })
  assert.equal(edBundle.payload.receiptCount, 1)
  assert.equal(edBundle.payload.records[0]!.patchRetests[0]!.verdict, 'fixed')
  assert.equal(edBundle.payload.records[0]!.transcriptSlices.length, 1)

  // Zero PII or bearer token leakage anywhere in serialized ZDR bundle
  const serialized = JSON.stringify(edBundle)
  assert.ok(!serialized.includes('victim@corp.example'), 'ZDR receipt bundle leaked email PII')
  assert.ok(!serialized.includes('123-45-6789'), 'ZDR receipt bundle leaked SSN PII')
  assert.ok(!serialized.includes('sk_live_shouldNeverLeak123456'), 'ZDR receipt bundle leaked bearer token')

  assert.deepEqual(
    verifyProofReceiptBundle(edBundle, { algorithm: 'ed25519', publicKey: edKeys.publicKey }),
    { valid: true, verifiedRecords: 1 },
  )

  // Tampering transcript fails verification
  const tamperedTranscript = structuredClone(edBundle)
  tamperedTranscript.payload.records[0]!.transcriptSlices[0]!.bodyPreview = 'tampered'
  assert.equal(verifyProofReceiptBundle(tamperedTranscript, { publicKey: edKeys.publicKey }).valid, false)

  // Cross-tenant export throws TenantIsolationError
  assert.throws(
    () => exportRunReceiptBundle(storage, runId, { tenantId: 'tenant-beta' }),
    TenantIsolationError,
  )

  // 2. Live authenticated HTTP ops endpoints via createGuardianLocalServer
  const local = createGuardianLocalServer({
    app: { fetch: () => new Response('ok', { status: 200 }) },
    directory: join(dir, 'server-auth'),
    port: 0,
    killSwitch: ks,
    store: storage,
  })

  await new Promise<void>(resolve => local.server.listen(0, '127.0.0.1', resolve))
  const port = (local.server.address() as AddressInfo).port
  // Re-bind allowedOrigins with actual ephemeral port by constructing server on the bound port
  await new Promise<void>(resolve => local.server.close(() => resolve()))

  const live = createGuardianLocalServer({
    app: { fetch: () => new Response('ok', { status: 200 }) },
    directory: join(dir, 'server-auth-live'),
    port,
    killSwitch: ks,
    store: storage,
  })
  await new Promise<void>(resolve => live.server.listen(port, '127.0.0.1', resolve))
  const baseUrl = `http://127.0.0.1:${port}`

  try {
    // Unauthenticated ops endpoints return JSON 401
    const unauthKs = await fetch(`${baseUrl}/api/ops/kill-switch`)
    assert.equal(unauthKs.status, 401)
    const unauthExport = await fetch(`${baseUrl}/api/runs/${runId}/receipts/export`)
    assert.equal(unauthExport.status, 401)

    // Authenticate via single-use bootstrap handshake
    const bootRes = await fetch(live.bootstrapUrl(baseUrl), { redirect: 'manual' })
    assert.equal(bootRes.status, 303)
    const setCookie = bootRes.headers.get('set-cookie') ?? ''
    const cookie = setCookie.split(';')[0]!
    assert.match(cookie, /^guardian_local=[a-f0-9]{64}$/)

    // GET /api/ops/kill-switch -> initially inactive
    const statusBefore = await fetch(`${baseUrl}/api/ops/kill-switch`, { headers: { cookie } })
    assert.equal(statusBefore.status, 200)
    assert.equal((await statusBefore.json() as { active: boolean }).active, false)

    // POST /api/ops/kill-switch -> trips live kill switch
    const tripRes = await fetch(`${baseUrl}/api/ops/kill-switch`, {
      method: 'POST',
      headers: { cookie, origin: baseUrl, 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'trip', reason: 'HTTP ops emergency stop' }),
    })
    assert.equal(tripRes.status, 200)
    const trippedState = await tripRes.json() as { active: boolean; reason: string }
    assert.equal(trippedState.active, true)
    assert.equal(trippedState.reason, 'HTTP ops emergency stop')
    assert.equal(ks.isActive(), true)

    // Reset via HTTP
    const resetRes = await fetch(`${baseUrl}/api/ops/kill-switch`, {
      method: 'POST',
      headers: { cookie, origin: baseUrl, 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'reset' }),
    })
    assert.equal(resetRes.status, 200)
    assert.equal((await resetRes.json() as { active: boolean }).active, false)
    assert.equal(ks.isActive(), false)

    // GET /api/runs/:runId/receipts/export?zdr=1&tenantId=tenant-alpha -> 200 signed ZDR bundle
    const exportOk = await fetch(`${baseUrl}/api/runs/${runId}/receipts/export?zdr=1&tenantId=tenant-alpha`, {
      headers: { cookie },
    })
    assert.equal(exportOk.status, 200)
    assert.match(exportOk.headers.get('cache-control') ?? '', /no-store/)
    assert.match(exportOk.headers.get('content-disposition') ?? '', /guardian-receipts-/)
    const httpBundle = await exportOk.json()
    const httpJson = JSON.stringify(httpBundle)
    assert.ok(!httpJson.includes('victim@corp.example'))
    assert.ok(!httpJson.includes('123-45-6789'))
    assert.ok(!httpJson.includes('sk_live_shouldNeverLeak123456'))

    // Verify default workspace HMAC signature matches
    const defaultSecret = createHash('sha256')
      .update(`guardian.receipt-export.v1\0${storage.workspace.id}`)
      .digest('hex')
    assert.deepEqual(
      verifyProofReceiptBundle(httpBundle, { algorithm: 'hmac-sha256', secret: defaultSecret }),
      { valid: true, verifiedRecords: 1 },
    )

    // Cross-tenant HTTP export -> 403 TENANT_ISOLATION_DENIED
    const exportDenied = await fetch(`${baseUrl}/api/runs/${runId}/receipts/export?tenantId=tenant-beta`, {
      headers: { cookie },
    })
    assert.equal(exportDenied.status, 403)
    const deniedBody = await exportDenied.json() as { code: string }
    assert.equal(deniedBody.code, 'TENANT_ISOLATION_DENIED')
  } finally {
    await new Promise<void>(resolve => live.server.close(() => resolve()))
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  }
})
