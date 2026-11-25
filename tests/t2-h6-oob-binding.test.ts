/**
 * Tier-2 OOB canary binding & late-promotion isolation regression suite
 * (CLAUDE_AUDIT H-6 & M-41 in `src/server/verify-rpc.ts`):
 *  - H-6: `oob.subscribe`, `oob.wait`, `oob.check`, and `prove.oob` reject fail-closed
 *    any unminted, foreign, or cross-attempt/cross-run canary token or mismatched ids.
 *  - M-41: `oob.wait` scopes late-callback promotion to the requested canary/token and
 *    neither consumes unrelated pending subscriptions nor discards sibling promotions.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { request as httpRequest } from 'node:http'
import test from 'node:test'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { evaluateClaims, VERIFY_NONCE_HEADER, VERIFY_RPC_HEADER, VerifyRpcServer } from '../src/server/verify-rpc.ts'
import type { VerifyClaim } from '../src/server/verify-rpc.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

interface RpcResponse {
  ok: boolean
  result?: unknown
  error?: string
}

function rpc(server: VerifyRpcServer, op: string, args: Record<string, unknown> = {}): Promise<RpcResponse> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ op, args })
    const req = httpRequest({
      socketPath: server.socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        [VERIFY_RPC_HEADER]: server.token,
        [VERIFY_NONCE_HEADER]: server.nonce,
      },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', chunk => chunks.push(Buffer.from(chunk)))
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcResponse) } catch (err) { reject(err) }
      })
    })
    req.once('error', reject)
    req.end(payload)
  })
}

function makeGrant(allowedOrigins: readonly string[] = ['http://127.0.0.1:1']): Grant {
  const allowed = new Set(allowedOrigins)
  return {
    canRead: origin => allowed.has(origin),
    audit: () => undefined,
    allowLocalLab: true,
    tier: 1,
    isStateChangeApproved: () => false,
  }
}

test('H-6: oob.subscribe, oob.wait, oob.check, and prove.oob reject unminted, foreign, and cross-attempt tokens fail-closed', async () => {
  const canary = new CanaryBroker()
  await canary.startLocalListener()
  const runId = `t2-h6-${randomUUID().slice(0, 8)}`
  const sessionA = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(),
    runId,
    assignmentId: 'assign-h6',
    nonce: `attempt-a-${randomUUID().slice(0, 8)}`,
    targetOrigins: ['http://127.0.0.1:1'],
    canary,
  })
  const sessionB = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(),
    runId,
    assignmentId: 'assign-h6',
    nonce: `attempt-b-${randomUUID().slice(0, 8)}`,
    targetOrigins: ['http://127.0.0.1:1'],
    canary,
  })
  await sessionA.start()
  await sessionB.start()
  try {
    // 1. Mint a foreign canary directly on CanaryBroker and trigger it so a real callback exists.
    const foreign = canary.mintCanary(runId, 'foreign-direct')
    const foreignCb = await fetch(foreign.httpUrl)
    assert.equal(foreignCb.status, 200)

    // 2. Mint + subscribe + trigger a canary in Session B (same runId, different attempt nonce).
    const mintBRes = await rpc(sessionB, 'oob', { action: 'mint', label: 'session-b' })
    assert.equal(mintBRes.ok, true, mintBRes.error ?? 'sessionB mint failed')
    const mintedB = mintBRes.result as { exchangeId: string; token: string; url: string; dnsHost: string; canaryId?: string }
    const subBRes = await rpc(sessionB, 'oob', { action: 'subscribe', token: mintedB.token, immediateMs: 50 })
    assert.equal(subBRes.ok, true, subBRes.error ?? 'sessionB subscribe failed')
    const subB = subBRes.result as { subscriptionId: string; createdAt: number }
    const cbB = await fetch(mintedB.url)
    assert.equal(cbB.status, 200)

    // 3. Session A must reject unminted, foreign, and cross-attempt tokens across subscribe, wait, check, and prove.oob finish.
    for (const badToken of ['unminted-bogus-token-0001', foreign.token, mintedB.token]) {
      const subBad = await rpc(sessionA, 'oob', { action: 'subscribe', token: badToken })
      assert.equal(subBad.ok, false, `subscribe must reject non-session token ${badToken}`)
      assert.match(subBad.error ?? '', /not minted in this verification session/i)

      const waitBad = await rpc(sessionA, 'oob', { action: 'wait', token: badToken, timeoutMs: 100 })
      assert.equal(waitBad.ok, false, `wait must reject non-session token ${badToken}`)
      assert.match(waitBad.error ?? '', /not minted in this verification session/i)

      const checkBad = await rpc(sessionA, 'oob', { action: 'check', token: badToken })
      assert.equal(checkBad.ok, false, `check must reject non-session token ${badToken}`)
      assert.match(checkBad.error ?? '', /not minted in this verification session/i)
    }

    const proveBad = await rpc(sessionA, 'prove.oob', {
      phase: 'finish',
      handle: { exchangeId: mintedB.exchangeId, token: mintedB.token, url: mintedB.url, dnsHost: mintedB.dnsHost },
      subscription: { subscriptionId: subB.subscriptionId, createdAt: subB.createdAt },
      timeoutMs: 100,
    })
    assert.equal(proveBad.ok, false, 'prove.oob finish must reject cross-attempt handle token')
    assert.match(proveBad.error ?? '', /not minted in this verification session/i)

    // 4. Session A's own minted token rejects mismatched runId/attemptId/canaryId/subscriptionId.
    const mintARes = await rpc(sessionA, 'oob', { action: 'mint', label: 'session-a' })
    assert.equal(mintARes.ok, true, mintARes.error ?? 'sessionA mint failed')
    const mintedA = mintARes.result as { exchangeId: string; token: string; url: string; canaryId?: string }

    const mismatchRun = await rpc(sessionA, 'oob', { action: 'subscribe', token: mintedA.token, runId: 'other-run' })
    assert.equal(mismatchRun.ok, false)
    assert.match(mismatchRun.error ?? '', /runId mismatch/i)

    const mismatchAttempt = await rpc(sessionA, 'oob', { action: 'subscribe', token: mintedA.token, attemptId: sessionB.nonce })
    assert.equal(mismatchAttempt.ok, false)
    assert.match(mismatchAttempt.error ?? '', /attemptId mismatch/i)

    const mismatchCanary = await rpc(sessionA, 'oob', { action: 'subscribe', token: mintedA.token, canaryId: 'spoofed-canary-id' })
    assert.equal(mismatchCanary.ok, false)
    assert.match(mismatchCanary.error ?? '', /canaryId mismatch/i)

    const subARes = await rpc(sessionA, 'oob', { action: 'subscribe', token: mintedA.token, immediateMs: 100 })
    assert.equal(subARes.ok, true)

    const foreignSubWait = await rpc(sessionA, 'oob', { action: 'wait', token: mintedA.token, subscriptionId: subB.subscriptionId, timeoutMs: 50 })
    assert.equal(foreignSubWait.ok, false)
    assert.match(foreignSubWait.error ?? '', /subscriptionId does not belong/i)

    // No rejected foreign/cross-attempt tokens may pollute Session A's transcript.
    assert.equal(sessionA.transcript.list().some(r => r.artifact?.token === mintedB.token || r.artifact?.token === foreign.token), false)
  } finally {
    await sessionA.close()
    await sessionB.close()
    await canary.stop()
    canary.closeOob()
  }
})

test('M-41: oob.wait promotes its own late callback without clobbering sibling subscriptions', async () => {
  const canary = new CanaryBroker()
  await canary.startLocalListener()
  const runId = `t2-m41-${randomUUID().slice(0, 8)}`
  const server = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(),
    runId,
    assignmentId: 'assign-m41',
    nonce: `attempt-${randomUUID().slice(0, 8)}`,
    targetOrigins: ['http://127.0.0.1:1'],
    canary,
  })
  await server.start()
  try {
    // 1. Same-session sibling subscriptions: both receive late callbacks, waited out-of-order.
    const mintA = (await rpc(server, 'oob', { action: 'mint', label: 'sibling-a' })).result as { exchangeId: string; token: string; url: string }
    const mintB = (await rpc(server, 'oob', { action: 'mint', label: 'sibling-b' })).result as { exchangeId: string; token: string; url: string }
    const subA = (await rpc(server, 'oob', { action: 'subscribe', token: mintA.token, immediateMs: 15 })).result as { subscriptionId: string; createdAt: number }
    const subB = (await rpc(server, 'oob', { action: 'subscribe', token: mintB.token, immediateMs: 15 })).result as { subscriptionId: string; createdAt: number }

    await new Promise(resolve => setTimeout(resolve, 35))
    assert.equal((await fetch(mintA.url)).status, 200)
    assert.equal((await fetch(mintB.url)).status, 200)

    // Wait on B first — must promote B and preserve A's late promotion rather than discarding it.
    const waitBRes = await rpc(server, 'oob', {
      action: 'wait',
      token: mintB.token,
      subscriptionId: subB.subscriptionId,
      subscriptionCreatedAt: subB.createdAt,
      immediateMs: 15,
      timeoutMs: 500,
    })
    assert.equal(waitBRes.ok, true, waitBRes.error ?? 'wait B failed')
    const waitB = waitBRes.result as { hit: boolean; promoted: boolean; stage: string; subscriptionId: string; token: string }
    assert.equal(waitB.hit, true)
    assert.equal(waitB.promoted, true)
    assert.equal(waitB.stage, 'late')
    assert.equal(waitB.subscriptionId, subB.subscriptionId)
    assert.equal(waitB.token, mintB.token)

    // Now wait on A — must still observe its own promoted late callback!
    const waitARes = await rpc(server, 'oob', {
      action: 'wait',
      token: mintA.token,
      subscriptionId: subA.subscriptionId,
      subscriptionCreatedAt: subA.createdAt,
      immediateMs: 15,
      timeoutMs: 500,
    })
    assert.equal(waitARes.ok, true, waitARes.error ?? 'wait A failed')
    const waitA = waitARes.result as { hit: boolean; promoted: boolean; stage: string; subscriptionId: string; token: string }
    assert.equal(waitA.hit, true)
    assert.equal(waitA.promoted, true)
    assert.equal(waitA.stage, 'late')
    assert.equal(waitA.subscriptionId, subA.subscriptionId)
    assert.equal(waitA.token, mintA.token)

    const claims: VerifyClaim[] = [
      { kind: 'oob', exchangeId: mintA.exchangeId, expectHit: true },
      { kind: 'oob', exchangeId: mintB.exchangeId, expectHit: true },
    ]
    const oracle = evaluateClaims(server.transcript, claims, { canary })
    assert.equal(oracle.passed, true, oracle.failures.join('; '))
  } finally {
    await server.close()
    await canary.stop()
    canary.closeOob()
  }
})

test('M-41: silent oob.wait on one session does not prematurely consume another session pending_oob callback', async () => {
  const canary = new CanaryBroker()
  await canary.startLocalListener()
  const sharedRunId = `t2-m41-shared-${randomUUID().slice(0, 8)}`
  const session1 = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(),
    runId: sharedRunId,
    assignmentId: 'assign-1',
    nonce: `n1-${randomUUID().slice(0, 8)}`,
    targetOrigins: ['http://127.0.0.1:1'],
    canary,
  })
  const session2 = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(),
    runId: sharedRunId,
    assignmentId: 'assign-2',
    nonce: `n2-${randomUUID().slice(0, 8)}`,
    targetOrigins: ['http://127.0.0.1:1'],
    canary,
  })
  await session1.start()
  await session2.start()
  try {
    const mint1 = (await rpc(session1, 'oob', { action: 'mint', label: 's1' })).result as { exchangeId: string; token: string; url: string }
    const sub1 = (await rpc(session1, 'oob', { action: 'subscribe', token: mint1.token, immediateMs: 15 })).result as { subscriptionId: string; createdAt: number }
    const mint2 = (await rpc(session2, 'oob', { action: 'mint', label: 's2' })).result as { exchangeId: string; token: string; url: string }
    const sub2 = (await rpc(session2, 'oob', { action: 'subscribe', token: mint2.token, immediateMs: 15 })).result as { subscriptionId: string; createdAt: number }

    await new Promise(resolve => setTimeout(resolve, 35))
    assert.equal((await fetch(mint1.url)).status, 200)

    // Session 2 waits on its silent token 2 — must NOT call promoteLate and consume Session 1's sub1.
    const wait2Res = await rpc(session2, 'oob', {
      action: 'wait',
      token: mint2.token,
      subscriptionId: sub2.subscriptionId,
      subscriptionCreatedAt: sub2.createdAt,
      immediateMs: 15,
      timeoutMs: 60,
    })
    assert.equal(wait2Res.ok, true)
    const wait2 = wait2Res.result as { hit: boolean; promoted: boolean; stage: string }
    assert.equal(wait2.hit, false)
    assert.equal(wait2.promoted, false)
    assert.equal(wait2.stage, 'pending')
    assert.ok(canary.oob.pending(sharedRunId).some(p => p.id === sub1.subscriptionId), 'sub1 must remain pending in OobRelay')

    // Session 1 now waits on token 1 and promotes its own late callback cleanly.
    const wait1Res = await rpc(session1, 'oob', {
      action: 'wait',
      token: mint1.token,
      subscriptionId: sub1.subscriptionId,
      subscriptionCreatedAt: sub1.createdAt,
      immediateMs: 15,
      timeoutMs: 250,
    })
    assert.equal(wait1Res.ok, true)
    const wait1 = wait1Res.result as { hit: boolean; promoted: boolean; stage: string; subscriptionId: string }
    assert.equal(wait1.hit, true)
    assert.equal(wait1.promoted, true)
    assert.equal(wait1.stage, 'late')
    assert.equal(wait1.subscriptionId, sub1.subscriptionId)
  } finally {
    await session1.close()
    await session2.close()
    await canary.stop()
    canary.closeOob()
  }
})
