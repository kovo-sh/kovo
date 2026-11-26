// @kernel @fixes R4-H-20
/**
 * R4-H-20 (WS-14) class-level stress & invariant guards for OOB callback quotas,
 * hard-capped protected pending budget, amortized pruning, bounded-memory per-IP
 * rate limiting, and explicit LIMIT bounds on token reads.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { performance } from 'node:perf_hooks'
import { DatabaseSync } from 'node:sqlite'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'

import { CanaryBroker } from '../src/server/canary-broker.ts'
import { OobRelay } from '../src/server/oob-relay.ts'
import { RUN_SAFETY_BUDGET_DEFAULTS } from '../src/server/run-safety-budgets.ts'

function makeToken(index: number): string {
  return `kovo-canary-${index.toString(16).padStart(24, '0')}`
}

function makeTempDir(t: TestContext, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

describe('R4-H-20: OOB callback quota-first ingest, protected budget, amortized pruning & IP rate limiting', () => {
  test('Guard 1: >10,000 distinct-path callbacks for ONE pending token stay strictly bounded with flat insert latency', (t: TestContext) => {
    let now = 1_700_000_000_000
    const relay = new OobRelay({ now: () => now })
    t.after(() => relay.close())

    const token = makeToken(1)
    relay.registerCanary({ runId: 'run-flood-1', canaryId: 'c-flood-1', token, assignmentId: 'a-1' })
    relay.subscribe({
      runId: 'run-flood-1',
      assignmentId: 'a-1',
      canaryId: 'c-flood-1',
      token,
      artifact: '',
      windowMs: 600_000,
    })

    const totalCallbacks = 12_500
    const batchSize = 2_500
    const batchDurationsMs: number[] = []
    let accepted = 0
    let firstAcceptedId = ''

    for (let batch = 0; batch < totalCallbacks / batchSize; batch += 1) {
      const t0 = performance.now()
      for (let j = 0; j < batchSize; j += 1) {
        const i = batch * batchSize + j
        // Rotate source IP across 5000+ addresses to stress per-token quota AND bounded LRU IP table.
        const ip = `10.${Math.floor(i / 250) % 250}.${i % 250}.1`
        const res = relay.recordCallback({
          token,
          sourceIp: ip,
          method: 'GET',
          path: `/flood/distinct/${i}`,
          query: `n=${i}`,
        })
        if (res.accepted && !res.duplicate) {
          accepted += 1
          if (!firstAcceptedId) firstAcceptedId = res.callback.callbackId
        } else if (!res.accepted) {
          assert.equal(res.rejection.reason, 'token_quota_exceeded')
        }
      }
      batchDurationsMs.push(performance.now() - t0)
    }

    const expectedCap = RUN_SAFETY_BUDGET_DEFAULTS.oobMaxCallbacksPerToken
    const status = relay.status()
    assert.equal(accepted, expectedCap, 'accepted count must equal oobMaxCallbacksPerToken')
    assert.equal(status.delivered, expectedCap, 'SQLite row count must stay strictly bounded by oobMaxCallbacksPerToken')
    assert.ok(status.delivered <= RUN_SAFETY_BUDGET_DEFAULTS.oobMaxProtectedCallbacks)
    assert.equal(status.rejected, 0, 'quota overflow must be counted in telemetry rather than inserted into oob_rejections')
    assert.equal(status.quota.droppedPerToken, totalCallbacks - expectedCap)
    assert.equal(status.quota.totalDropped, totalCallbacks - expectedCap)
    assert.ok(
      status.quota.trackedSourceIps <= status.quota.budgets.maxTrackedSourceIps,
      `trackedSourceIps (${status.quota.trackedSourceIps}) must stay <= LRU cap (${status.quota.budgets.maxTrackedSourceIps})`,
    )
    assert.ok(
      status.quota.pruneRuns <= 4,
      `amortized pruning must not run on every insert/overflow (pruneRuns=${status.quota.pruneRuns})`,
    )

    // Flat latency invariant: later 2,500-insert batches must not show O(n) growth over early batches.
    const totalMs = batchDurationsMs.reduce((sum, ms) => sum + ms, 0)
    const batch2Ms = batchDurationsMs[1]!
    const lastBatchMs = batchDurationsMs[batchDurationsMs.length - 1]!
    assert.ok(
      totalMs < 2_500,
      `12,500 flooded callbacks must complete quickly (<2500ms), got ${totalMs.toFixed(1)}ms (${batchDurationsMs.map(v => v.toFixed(1)).join(', ')})`,
    )
    assert.ok(
      lastBatchMs < Math.max(batch2Ms * 4, 250),
      `insert latency must stay flat across 2,500-insert batches: batches=${batchDurationsMs.map(v => v.toFixed(1)).join(', ')}ms`,
    )

    // Idempotent redelivery of an already-accepted callback still succeeds when token is at quota.
    const dup = relay.recordCallback({
      token,
      callbackId: firstAcceptedId,
      sourceIp: '198.51.100.1',
      method: 'GET',
      path: '/flood/distinct/0',
      query: 'n=0',
    })
    assert.equal(dup.accepted, true)
    assert.equal(dup.duplicate, true)

    // Pending subscription still promotes cleanly from the retained callbacks.
    const promotions = relay.promoteLate({ runId: 'run-flood-1', now })
    assert.equal(promotions.length, 1)
    assert.equal(promotions[0]!.callback.callbackId, firstAcceptedId)
  })

  test('Guard 1b: >10,000 callbacks from a single IP hit per-token quota then IP rate limit with zero SQLite bloat', (t: TestContext) => {
    const relay = new OobRelay()
    t.after(() => relay.close())

    const token = makeToken(2)
    relay.registerCanary({ runId: 'run-single-ip', canaryId: 'c-single-ip', token })
    relay.subscribe({
      runId: 'run-single-ip',
      assignmentId: 'a-1',
      canaryId: 'c-single-ip',
      token,
      artifact: '',
    })

    const total = 10_500
    for (let i = 0; i < total; i += 1) {
      relay.recordCallback({
        token,
        sourceIp: '203.0.113.77',
        path: `/same-ip/${i}`,
      })
    }

    const status = relay.status()
    assert.equal(status.delivered, RUN_SAFETY_BUDGET_DEFAULTS.oobMaxCallbacksPerToken)
    assert.equal(
      status.quota.droppedPerToken,
      RUN_SAFETY_BUDGET_DEFAULTS.oobMaxCallbacksPerIpWindow - RUN_SAFETY_BUDGET_DEFAULTS.oobMaxCallbacksPerToken,
    )
    assert.equal(
      status.quota.droppedPerIp,
      total - RUN_SAFETY_BUDGET_DEFAULTS.oobMaxCallbacksPerIpWindow,
    )
    assert.equal(status.quota.totalDropped, total - RUN_SAFETY_BUDGET_DEFAULTS.oobMaxCallbacksPerToken)
    assert.equal(status.rejected, 0)
  })

  test('Guard 2: multi-token flood stays bounded by oobMaxCallbacksPerRun & oobMaxProtectedCallbacks while isolating healthy tokens', (t: TestContext) => {
    const relay = new OobRelay({
      maxCallbacksPerToken: 16,
      maxProtectedCallbacks: 40,
      maxCallbacksPerRun: 60,
      maxCallbacksPerIpWindow: 1_000,
    })
    t.after(() => relay.close())

    // Token A floods 30 callbacks -> capped at 16 (per-token cap).
    const tokenA = makeToken(10)
    relay.registerCanary({ runId: 'run-multi', canaryId: 'c-a', token: tokenA })
    relay.subscribe({ runId: 'run-multi', assignmentId: 'a-1', canaryId: 'c-a', token: tokenA, artifact: '' })
    let acceptedA = 0
    for (let i = 0; i < 30; i += 1) {
      const res = relay.recordCallback({ token: tokenA, sourceIp: '198.51.100.1', path: `/a/${i}` })
      if (res.accepted && !res.duplicate) acceptedA += 1
      else if (!res.accepted) assert.equal(res.rejection.reason, 'token_quota_exceeded')
    }
    assert.equal(acceptedA, 16)

    // Healthy Token B in the SAME run still succeeds cleanly after Token A hit its per-token cap!
    const tokenB = makeToken(11)
    relay.registerCanary({ runId: 'run-multi', canaryId: 'c-b', token: tokenB })
    relay.subscribe({ runId: 'run-multi', assignmentId: 'a-1', canaryId: 'c-b', token: tokenB, artifact: '' })
    let acceptedB = 0
    for (let i = 0; i < 16; i += 1) {
      const res = relay.recordCallback({ token: tokenB, sourceIp: '198.51.100.2', path: `/b/${i}` })
      assert.equal(res.accepted, true, 'healthy distinct token must succeed when sibling token is at cap')
      if (res.accepted && !res.duplicate) acceptedB += 1
    }
    assert.equal(acceptedB, 16)

    // Token C (pending subscription) hits the hard-capped protected budget at 16 + 16 + 8 = 40.
    const tokenC = makeToken(12)
    relay.registerCanary({ runId: 'run-multi', canaryId: 'c-c', token: tokenC })
    relay.subscribe({ runId: 'run-multi', assignmentId: 'a-1', canaryId: 'c-c', token: tokenC, artifact: '' })
    let acceptedC = 0
    let protectedDrops = 0
    for (let i = 0; i < 16; i += 1) {
      const res = relay.recordCallback({ token: tokenC, sourceIp: '198.51.100.3', path: `/c/${i}` })
      if (res.accepted && !res.duplicate) acceptedC += 1
      else if (!res.accepted) {
        assert.equal(res.rejection.reason, 'protected_quota_exceeded')
        protectedDrops += 1
      }
    }
    assert.equal(acceptedC, 8, 'protected budget must hard-cap total pending callbacks at 40')
    assert.equal(protectedDrops, 8)
    assert.equal(relay.quotaTelemetry().droppedProtected, 8)

    // Unprotected tokens (registered without pending_oob) can still consume up to maxCallbacksPerRun = 60, then stop.
    let unprotectedAccepted = 0
    let runQuotaDrops = 0
    for (let tIdx = 0; tIdx < 3; tIdx += 1) {
      const tok = makeToken(20 + tIdx)
      relay.registerCanary({ runId: 'run-multi', canaryId: `c-u-${tIdx}`, token: tok })
      for (let i = 0; i < 12; i += 1) {
        const res = relay.recordCallback({ token: tok, sourceIp: '198.51.100.4', path: `/u/${tIdx}/${i}` })
        if (res.accepted && !res.duplicate) unprotectedAccepted += 1
        else if (!res.accepted) {
          assert.equal(res.rejection.reason, 'run_quota_exceeded')
          runQuotaDrops += 1
        }
      }
    }
    assert.equal(unprotectedAccepted, 20, 'run total (40 protected + 20 unprotected) must cap at maxCallbacksPerRun=60')
    assert.equal(runQuotaDrops, 16)
    assert.equal(relay.status().delivered, 60)
    assert.equal(relay.quotaTelemetry().droppedPerRun, 16)

    // A separate healthy run is NOT starved when run-multi hits its per-run quota.
    const otherRunToken = makeToken(99)
    relay.registerCanary({ runId: 'run-healthy', canaryId: 'c-healthy', token: otherRunToken })
    const healthyRes = relay.recordCallback({ token: otherRunToken, sourceIp: '198.51.100.5', path: '/healthy' })
    assert.equal(healthyRes.accepted, true, 'separate healthy run must still accept callbacks')
  })

  test('Guard 3a: CanaryBroker HTTP ingest enforces per-IP rate limit with 429 and resets after window', async (t: TestContext) => {
    let now = 1_800_000_000_000
    const broker = new CanaryBroker({
      now: () => now,
      maxCallbacksPerIpWindow: 10,
      ipRateLimitWindowMs: 10_000,
      maxTrackedSourceIps: 16,
    })
    t.after(async () => {
      await broker.stopListener()
      broker.closeOob()
    })

    const info = await broker.startListener({ host: '127.0.0.1', port: 0 })
    assert.ok(info.localBaseUrl)
    const canary = broker.mintCanary('run-http-rl', 'ssrf-probe', 'https://target.example')

    let okCount = 0
    let limitedCount = 0
    for (let i = 0; i < 15; i += 1) {
      const resp: Response = await fetch(`${info.localBaseUrl}/c/${canary.token}?n=${i}`, {
        signal: AbortSignal.timeout(5_000),
      })
      if (resp.status === 200) {
        assert.equal(await resp.text(), 'kovo-canary-ok')
        okCount += 1
      } else {
        assert.equal(resp.status, 429)
        assert.equal(await resp.text(), 'kovo-canary-rate-limited')
        assert.ok(Number(resp.headers.get('retry-after')) >= 1)
        limitedCount += 1
      }
    }

    assert.equal(okCount, 10)
    assert.equal(limitedCount, 5)
    assert.equal(broker.oobQuotaTelemetry().droppedPerIp, 5)
    assert.equal(broker.relayStatus().delivered, 10)

    // Advance past ipRateLimitWindowMs: requests from the same IP are accepted again.
    now += 10_001
    const afterWindow: Response = await fetch(`${info.localBaseUrl}/c/${canary.token}?n=after`, {
      signal: AbortSignal.timeout(5_000),
    })
    assert.equal(afterWindow.status, 200)
    assert.equal(broker.relayStatus().delivered, 11)
  })

  test('Guard 3b: bounded LRU per-IP tracker never grows past maxTrackedSourceIps under spoofed-IP flood', (t: TestContext) => {
    let now = 1_900_000_000_000
    const relay = new OobRelay({
      now: () => now,
      maxCallbacksPerIpWindow: 5,
      ipRateLimitWindowMs: 60_000,
      maxTrackedSourceIps: 64,
    })
    t.after(() => relay.close())

    for (let i = 0; i < 5_000; i += 1) {
      const ip = `192.${Math.floor(i / 250) % 250}.${i % 250}.1`
      const res = relay.consumeIpRateLimit(ip, now)
      assert.equal(res.allowed, true)
    }

    const telemetry = relay.quotaTelemetry()
    assert.ok(
      telemetry.trackedSourceIps <= 64,
      `trackedSourceIps (${telemetry.trackedSourceIps}) must remain strictly <= 64`,
    )
    assert.equal(telemetry.trackedSourceIps, 64)
  })

  test('Guard 3c: callbacksForToken and promoteLate enforce explicit SQL LIMIT even on legacy oversized DBs', (t: TestContext) => {
    const dir = makeTempDir(t, 'kovo-r4-oob-limit-')
    const token = makeToken(77)

    // Initialize schema then close so we can seed 250 legacy rows directly into SQLite.
    const initRelay = new OobRelay({ directory: dir, maxCallbacksPerToken: 10 })
    initRelay.registerCanary({ runId: 'run-legacy', canaryId: 'c-legacy', token })
    initRelay.subscribe({
      runId: 'run-legacy',
      assignmentId: 'a-legacy',
      canaryId: 'c-legacy',
      token,
      artifact: 'art-match',
      windowMs: 600_000,
    })
    initRelay.close()

    const db = new DatabaseSync(join(dir, 'oob-relay.sqlite'))
    try {
      const stmt = db.prepare(`
        INSERT INTO oob_callbacks (
          callback_id, token, protocol, source_ip, remote_ip, method, path, query,
          artifact, run_id, assignment_id, canary_id, received_at, claimed_by, detail
        ) VALUES (?, ?, 'http', '127.0.0.1', '127.0.0.1', 'GET', ?, NULL, ?, 'run-legacy', 'a-legacy', 'c-legacy', ?, NULL, NULL)
      `)
      const baseTs = Date.now()
      for (let i = 0; i < 250; i += 1) {
        // Only row #100 carries the matching artifact 'art-match'; earlier rows carry 'art-other'.
        const artifact = i === 100 ? 'art-match' : 'art-other'
        stmt.run(`legacy_cb_${i}`, token, `/legacy/${i}`, artifact, baseTs + i)
      }
    } finally {
      db.close()
    }

    const relay = new OobRelay({ directory: dir, maxCallbacksPerToken: 10 })
    t.after(() => relay.close())

    // callbacksForToken obeys default maxCallbacksPerToken LIMIT (10) and explicit smaller LIMIT (4).
    assert.equal(relay.callbacksForToken(token).length, 10)
    assert.equal(relay.callbacksForToken(token, 4).length, 4)

    // Cold-cache restart safety: new ingest for this already-oversized token rejects immediately before insert.
    const overflow = relay.recordCallback({
      token,
      sourceIp: '127.0.0.1',
      artifact: 'art-match',
      path: '/post-restart',
    })
    assert.equal(overflow.accepted, false)
    if (!overflow.accepted) assert.equal(overflow.rejection.reason, 'token_quota_exceeded')

    // promoteLate obeys explicit LIMIT: scanning only first 10 rows does NOT pull row #100 into memory!
    const boundedPromote = relay.promoteLate({ runId: 'run-legacy', maxCallbacksPerToken: 10 })
    assert.equal(boundedPromote.length, 0, 'promoteLate with LIMIT 10 must not scan past row 10 to row #100')

    // With a higher explicit limit covering row #100, promotion finds and claims row #100.
    const widePromote = relay.promoteLate({ runId: 'run-legacy', maxCallbacksPerToken: 120 })
    assert.equal(widePromote.length, 1)
    assert.equal(widePromote[0]!.callback.callbackId, 'legacy_cb_100')
  })

  test('Guard 4: amortized pruning excludes protected pending rows from unprotected counts and never starves protected rows', (t: TestContext) => {
    let now = 2_000_000_000_000
    const relay = new OobRelay({
      now: () => now,
      maxUnclaimedCallbacks: 10,
      maxProtectedCallbacks: 50,
      maxCallbacksPerToken: 50,
      maxCallbacksPerRun: 200,
      maxCallbacksPerIpWindow: 500,
      pruneBatchSize: 20,
      pruneIntervalMs: 60_000,
      unclaimedCallbackTtlMs: 0,
    })
    t.after(() => relay.close())

    // Insert 30 protected callbacks (> maxUnclaimedCallbacks=10, <= maxProtectedCallbacks=50).
    const protectedTok = makeToken(500)
    relay.registerCanary({ runId: 'run-prot', canaryId: 'c-prot', token: protectedTok })
    relay.subscribe({ runId: 'run-prot', assignmentId: 'a-1', canaryId: 'c-prot', token: protectedTok, artifact: '' })
    for (let i = 0; i < 30; i += 1) {
      const rec = relay.recordCallback({ token: protectedTok, sourceIp: '127.0.0.1', path: `/prot/${i}` })
      assert.equal(rec.accepted, true)
    }

    // Insert 15 orphaned unprotected callbacks (> maxUnclaimedCallbacks=10).
    const orphanTok = makeToken(501)
    relay.registerCanary({ runId: 'run-orph', canaryId: 'c-orph', token: orphanTok })
    for (let i = 0; i < 15; i += 1) {
      now += 1
      const rec = relay.recordCallback({ token: orphanTok, sourceIp: '127.0.0.1', path: `/orph/${i}` })
      assert.equal(rec.accepted, true)
    }

    // Amortized pruning ran at most a handful of times (batchSize = 20 across 45 writes -> 2 runs).
    assert.ok(relay.quotaTelemetry().pruneRuns <= 3, `expected amortized pruneRuns <= 3, got ${relay.quotaTelemetry().pruneRuns}`)

    // Explicit pruneNow evicts orphaned rows down to maxUnclaimedCallbacks=10 while keeping all 30 protected rows.
    relay.pruneNow(now)
    assert.equal(relay.callbacksForToken(protectedTok).length, 30, 'all 30 protected callbacks must remain intact')
    assert.equal(relay.callbacksForToken(orphanTok).length, 10, 'orphaned callbacks must be pruned to maxUnclaimedCallbacks=10')
  })
})
