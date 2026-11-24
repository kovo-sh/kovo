/**
 * v7 M0 — ProofReceipt unification tests.
 *
 * Cut 1 retires the agent-facing DSL plumbing (prove_* bindings, Phase-3 refinement queues).
 * Cut 2 adds the receipt primitive: verifyReceipt() fixtures (boundary, persisted mutation, OOB,
 * timing), the replay/retest adapter, and the async `pending_oob` promotion path.
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { once } from 'node:events'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { Execution, probeCanaryClass } from '../src/server/execution.ts'
import {
  applyReceiptGate,
  buildReplayReceipt,
  retestReplaySpec,
  verifyReplaySpec,
} from '../src/server/replay-verifier.ts'
import {
  proofReceiptSchema,
  verifyReceipt,
} from '../src/server/proof-receipt.ts'
import type { ImpactStep, ReceiptTranscript, ReceiptTranscriptEntry } from '../src/server/proof-receipt.ts'
import { Store } from '../src/server/store.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import { makeLabGrant, setupApprovedRun } from './v4-tier-helpers.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const executionSource = readFileSync(join(repoRoot, 'src/server/execution.ts'), 'utf8')

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

function makeStore(t: { after: (fn: () => void) => void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-v7-receipt-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })
  return storage
}

function step(partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: { handle: partial.actor?.handle ?? 'anon', role: partial.actor?.role ?? null, tenant: partial.actor?.tenant ?? null, auth: 'unknown', sameSite: null },
    ...(partial.route !== undefined ? { route: partial.route } : {}),
    ...(partial.pathAndQuery !== undefined ? { pathAndQuery: partial.pathAndQuery } : {}),
    ...(partial.json !== undefined ? { json: partial.json } : {}),
    ...(partial.body !== undefined ? { body: partial.body } : {}),
    ...(partial.requestJson !== undefined ? { requestJson: partial.requestJson } : {}),
    ...(partial.requestHeaders !== undefined ? { requestHeaders: partial.requestHeaders } : {}),
  }
}

function entry(exchangeId: string, s: ImpactStep, extra: Partial<ReceiptTranscriptEntry> = {}): ReceiptTranscriptEntry {
  return { exchangeId, step: s, ...extra }
}

// ============================================================================
// Cut 1 — deletions
// ============================================================================

test('M0 cut 1: agent-facing prove_* compiler bindings are gone from Execution', () => {
  assert.ok(!executionSource.includes('submitProofSpec'))
  assert.ok(!executionSource.includes('prove_authz_read_diff:'))
  assert.ok(!executionSource.includes('prove_state_mutation_diff:'))
  assert.ok(!executionSource.includes('prove_business_invariant:'))
  assert.ok(!executionSource.includes('prove_canary_or_redirect:'))
  assert.ok(!executionSource.includes("from './proof-tools.ts'"))
})

test('M0 cut 1: Phase-3 DSL refinement queue and fallback exposure are gone', () => {
  assert.ok(!executionSource.includes('refinementEligible'))
  assert.ok(!executionSource.includes('runPhase3RefinementJob'))
  assert.ok(!executionSource.includes('phase3RefinementAttempt'))
  assert.ok(!/stepId: `refine:/.test(executionSource))
  assert.ok(!executionSource.includes('Phase-3 refinement'))
})

test('M0: replay_spec_id stays nullable for historical findings', () => {
  const schema = readFileSync(join(repoRoot, 'src/server/schema.ts'), 'utf8')
  assert.match(schema, /replaySpecId: text\('replay_spec_id'\)(?!\.notNull)/)
})

// ============================================================================
// Cut 2 — receipt schema + boundary
// ============================================================================

const baseReceipt = {
  vulnClass: 'business_logic',
  target: { origin: 'https://app.example.invalid', method: 'PATCH', pathAndQuery: '/api/invoices/42' },
  exchangeIds: ['ex-before', 'ex-write', 'ex-after'],
  oobEventIds: [],
  browserTraceIds: [],
  claimedDelta: 'The owner_id field moved from u1 to u2 and persisted.',
}

test('M0 receipt: schema rejects an empty claimed delta, missing ids, and non-scoped origins', () => {
  assert.equal(proofReceiptSchema.safeParse(baseReceipt).success, true)
  assert.equal(proofReceiptSchema.safeParse({ ...baseReceipt, claimedDelta: '  ' }).success, false)
  assert.equal(proofReceiptSchema.safeParse({ ...baseReceipt, exchangeIds: [''] }).success, false)
  assert.equal(proofReceiptSchema.safeParse({ ...baseReceipt, target: { origin: 'ftp://x' } }).success, false)
  assert.equal(proofReceiptSchema.safeParse({ ...baseReceipt, oobEventIds: Array(17).fill('id') }).success, false)
})

test('M0 receipt boundary: a cited exchange absent from the transcript is rejected', () => {
  const transcript: ReceiptTranscript = {
    entries: [
      entry('ex-before', step({ id: 'b1', arm: 'control', method: 'GET', status: 200, json: { owner_id: 'u1' } })),
      entry('ex-write', step({ id: 'p1', arm: 'probe', method: 'PATCH', status: 200, requestJson: { owner_id: 'u2' }, json: { owner_id: 'u2' } })),
      // ex-after is deliberately missing
    ],
  }
  const verdict = verifyReceipt(baseReceipt, transcript)
  assert.equal(verdict.confirmed, false)
  assert.match(verdict.reason, /ex-after/)
})

test('M0 receipt: persisted protected-field mutation confirms; an unchanged readback is rejected', () => {
  const transcript: ReceiptTranscript = {
    entries: [
      entry('ex-before', step({ id: 'b1', arm: 'control', method: 'GET', status: 200, json: { owner_id: 'u1', status: 'open' } })),
      entry('ex-write', step({ id: 'p1', arm: 'probe', method: 'PATCH', status: 200, requestJson: { owner_id: 'u2' }, json: { owner_id: 'u2', status: 'open' } })),
      entry('ex-after', step({ id: 'a1', arm: 'control', method: 'GET', status: 200, json: { owner_id: 'u2', status: 'open' } })),
    ],
  }
  const confirmed = verifyReceipt(baseReceipt, transcript)
  assert.equal(confirmed.confirmed, true, confirmed.reason)
  assert.equal(confirmed.rule, 'impact')

  const noop: ReceiptTranscript = {
    entries: transcript.entries!.map((item, index) => index === 2
      ? entry('ex-after', step({ id: 'a1', arm: 'control', method: 'GET', status: 200, json: { owner_id: 'u1', status: 'open' } }))
      : item),
  }
  const rejected = verifyReceipt(baseReceipt, noop)
  assert.equal(rejected.confirmed, false)
  assert.match(rejected.reason, /before\/after readback|state echo|not impact|No before/i)
})

test('M0 receipt: an OOB callback confirms only when a cited exchange carried the delivered token', () => {
  const token = 'guardian-canary-0123456789abcdef01234567'
  const receipt = {
    vulnClass: 'ssrf',
    target: { origin: 'http://127.0.0.1:7777', method: 'POST', pathAndQuery: '/v1/integrations/webhook-test' },
    exchangeIds: ['ex-inject'],
    oobEventIds: ['sub-1'],
    browserTraceIds: [],
    claimedDelta: 'The stored URL was fetched after the 202 response.',
  }
  const transcript: ReceiptTranscript = {
    entries: [entry('ex-inject', step({
      id: 'p1', arm: 'probe', method: 'POST', status: 202,
      pathAndQuery: '/v1/integrations/webhook-test',
      body: JSON.stringify({ url: `http://relay.invalid/c/${token}` }),
    }), { carrierText: `POST /v1/integrations/webhook-test\n{"url":"http://relay.invalid/c/${token}"}` })],
    oobEvents: [{ id: 'sub-1', canaryId: 'c-1', token, targetOrigin: 'http://127.0.0.1:7777', delivered: true, stage: 'late', receivedAtMs: 30_000, latencyMs: 30_000 }],
  }
  const confirmed = verifyReceipt(receipt, transcript)
  assert.equal(confirmed.confirmed, true, confirmed.reason)

  const wrongToken: ReceiptTranscript = {
    ...transcript,
    entries: [entry('ex-inject', step({
      id: 'p1', arm: 'probe', method: 'POST', status: 202,
      pathAndQuery: '/v1/integrations/webhook-test',
      body: JSON.stringify({ url: 'http://safe.invalid/' }),
    }), { carrierText: 'POST /v1/integrations/webhook-test\n{"url":"http://safe.invalid/"}' })],
  }
  assert.equal(verifyReceipt(receipt, wrongToken).confirmed, false)

  const notDelivered: ReceiptTranscript = {
    ...transcript,
    oobEvents: [{ ...transcript.oobEvents![0]!, delivered: false }],
  }
  assert.equal(verifyReceipt(receipt, notDelivered).confirmed, false)

  const wrongOrigin: ReceiptTranscript = {
    ...transcript,
    oobEvents: [{ ...transcript.oobEvents![0]!, targetOrigin: 'http://other.invalid' }],
  }
  assert.equal(verifyReceipt(receipt, wrongOrigin).confirmed, false)
})

test('M0 receipt: timing confirms only a stable >3x probe separation', () => {
  const receipt = {
    vulnClass: 'blind_sqli',
    target: { origin: 'https://app.example.invalid', method: 'GET', pathAndQuery: '/search?q=' },
    exchangeIds: ['ctl', 'prb'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'The injected comparison adds a measurable delay.',
  }
  const make = (controlMs: number, probeMs: number): ReceiptTranscript => ({
    entries: [
      entry('ctl', step({ id: 'c1', arm: 'control', method: 'GET', status: 200 }), { durationMs: controlMs }),
      entry('prb', step({ id: 'p1', arm: 'probe', method: 'GET', status: 200 }), { durationMs: probeMs }),
    ],
  })
  assert.equal(verifyReceipt(receipt, make(40, 2_400)).confirmed, true)
  assert.equal(verifyReceipt(receipt, make(40, 500)).confirmed, false)
  assert.equal(verifyReceipt(receipt, make(1_500, 3_000)).confirmed, false)
})

test('M0 receipt: a static/unknown class never becomes runtime_confirmed', () => {
  const receipt = {
    vulnClass: 'static_ast_proof',
    target: { origin: 'https://app.example.invalid' },
    exchangeIds: [],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'A sink exists in source.',
  }
  const verdict = verifyReceipt(receipt, {})
  assert.equal(verdict.confirmed, false)
  assert.match(verdict.reason, /No confirmation rule/)
})

// ============================================================================
// Cut 2 — replay/retest adapter + promotion classifier
// ============================================================================

test('M0 receipt: the floor adapter builds a receipt and strict mode can only downgrade', () => {
  const spec = {
    kind: 'http_chain',
    origin: 'https://app.example.invalid',
    title: 'Business logic owner reassignment',
    category: 'business-logic-race',
    cwe: 'CWE-840',
    impact: 'A caller reassigns the object owner.',
    expectedImpactEvents: ['invariant_violation'],
    steps: [
      { id: 'b1', role: 'control', request: { origin: 'https://app.example.invalid', method: 'GET', pathAndQuery: '/api/invoices/42' } },
      { id: 'p1', role: 'probe', request: { origin: 'https://app.example.invalid', method: 'PATCH', pathAndQuery: '/api/invoices/42', jsonBody: { owner_id: 'u2' } } },
      { id: 'a1', role: 'control', request: { origin: 'https://app.example.invalid', method: 'GET', pathAndQuery: '/api/invoices/42' } },
    ],
  } as unknown as DeclarativeReplaySpec
  const exchangeIds = ['ex-b1', 'ex-p1', 'ex-a1']
  const built = buildReplayReceipt({
    spec,
    evidencePayload: {
      steps: {
        b1: { id: 'b1', role: 'control', exchangeId: 'ex-b1', status: 200, json: { owner_id: 'u1' }, actorRole: 'member' },
        p1: { id: 'p1', role: 'probe', exchangeId: 'ex-p1', status: 200, json: { owner_id: 'u2' }, actorRole: 'member' },
        a1: { id: 'a1', role: 'control', exchangeId: 'ex-a1', status: 200, json: { owner_id: 'u2' }, actorRole: 'member' },
      },
    },
    exchangeIds,
    exchanges: [],
  })
  assert.ok(built, 'adapter must produce a receipt for a persisted mutation')
  const verification = verifyReceipt(built.receipt, built.transcript)
  assert.equal(verification.confirmed, true, verification.reason)

  const strict = applyReceiptGate({
    mode: 'strict',
    verdict: 'confirmed',
    outcome: { confirmed: true, controlPassed: true, observed: 'x', expected: 'y' },
    receipt: built.receipt,
    verification: { ...verification, confirmed: false, reason: 'transcript mismatch' },
  })
  assert.equal(strict.verdict, 'inconclusive')
  assert.equal(strict.outcome.confirmed, false)
  assert.ok(strict.check)

  const shadow = applyReceiptGate({
    mode: 'shadow',
    verdict: 'confirmed',
    outcome: { confirmed: true, controlPassed: true, observed: 'x', expected: 'y' },
    receipt: built.receipt,
    verification: { ...verification, confirmed: false, reason: 'transcript mismatch' },
  })
  assert.equal(shadow.verdict, 'confirmed')
  assert.equal(shadow.outcome.confirmed, true)
})

test('M0: canary purpose classifier only accepts probe-minted ssrf/xxe canaries', () => {
  assert.deepEqual(probeCanaryClass('engine:ssrf:url (http://127.0.0.1:7777)'), { vulnClass: 'ssrf', origin: 'http://127.0.0.1:7777', param: 'url' })
  assert.deepEqual(probeCanaryClass('ssrf:callback:dns (https://api.example)'), { vulnClass: 'ssrf', origin: 'https://api.example', param: 'callback' })
  assert.deepEqual(probeCanaryClass('xxe:general_entity (https://api.example)'), { vulnClass: 'xxe', origin: 'https://api.example', param: null })
  assert.equal(probeCanaryClass('jwt-jku (https://api.example)'), null)
  assert.equal(probeCanaryClass('template:openapi-31 (https://api.example)'), null)
  assert.equal(probeCanaryClass('engine:ssrf:url'), null)
})

// ============================================================================
// Cut 2 — real verify + patch retest carry the receipt
// ============================================================================

test('M0: verifyReplaySpec and retestReplaySpec confirm through the receipt on a real replay', async (t) => {
  let state = { owner_id: 'u1', status: 'open' }
  const server = createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/api/invoices/42') {
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify(state))
      return
    }
    if (req.method === 'PATCH' && req.url === '/api/invoices/42') {
      let body = ''
      req.on('data', chunk => { body += chunk })
      req.on('end', () => {
        try { state = { ...state, ...JSON.parse(body) } } catch { /* ignore */ }
        res.setHeader('content-type', 'application/json')
        res.end(JSON.stringify(state))
      })
      return
    }
    res.statusCode = 404
    res.end('{}')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as { port: number }).port
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolve => server.close(() => resolve()))
  })
  const origin = `http://127.0.0.1:${port}`
  const spec = {
    version: 1,
    kind: 'http_chain',
    origin,
    title: 'Business logic owner reassignment',
    category: 'business-logic-race',
    cwe: 'CWE-840',
    severity: 'high',
    severityRationale: 'An owner field moves outside the workflow rules.',
    impact: 'A caller reassigns the object owner and the change persists.',
    remediation: 'Bind owner changes to an authorized workflow transition.',
    recheckInstructions: 'Replay the before/write/after chain after the patch.',
    assertionsJq: '{ controlPassed: (.steps.p1.status == 200), confirmed: (.steps.a1.json.owner_id == "u2"), observed: ("owner=" + (.steps.a1.json.owner_id | tostring)), expected: "owner=u1" }',
    expectedImpactEvents: ['invariant_violation'],
    steps: [
      { id: 'b1', role: 'control', description: 'Read before', expectedStatus: 200, request: { origin, method: 'GET', pathAndQuery: '/api/invoices/42', followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'Reassign owner', expectedStatus: 200, request: { origin, method: 'PATCH', pathAndQuery: '/api/invoices/42', jsonBody: { owner_id: 'u2' }, followRedirects: false } },
      { id: 'a1', role: 'control', description: 'Read after', expectedStatus: 200, request: { origin, method: 'GET', pathAndQuery: '/api/invoices/42', followRedirects: false } },
    ],
  } as unknown as DeclarativeReplaySpec
  const grant = makeLabGrant(origin, { tier: 3 })
  const params = {
    spec,
    broker: new RequestBroker({ rejectUnauthorized: false }),
    backend: new LocalJqBackend(),
    grant,
    signal: AbortSignal.timeout(20_000),
  }
  const verified = await verifyReplaySpec(params)
  assert.equal(verified.verdict, 'confirmed', verified.outcome.reason ?? 'no reason')
  assert.ok(verified.receipt, 'a confirmed impact replay must carry a receipt')
  assert.equal(verified.receipt!.verification.confirmed, true, verified.receipt!.verification.reason)
  assert.equal(verified.receipt!.mode, 'shadow')
  assert.equal(verified.receipt!.receipt.exchangeIds.length, 3)

  state = { owner_id: 'u1', status: 'open' }
  const retest = await retestReplaySpec(params)
  assert.equal(retest.verdict, 'reproduced', retest.replay.outcome.reason ?? 'no reason')
  assert.equal(retest.replay.receipt?.verification.confirmed, true)
})

// ============================================================================
// Cut 2 — pending_oob promotion becomes a runtime_confirmed finding
// ============================================================================

test('M0: a late pending_oob callback for an SSRF canary becomes a runtime_confirmed finding', async (t) => {
  const storage = makeStore(t)
  const origin = 'http://127.0.0.1:7777'
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 2 })
  const run = storage.run(runId)
  storage.updateRun(runId, { status: 'running', phase: 'verification' })
  const asset = run.candidates[0]!
  const worker = storage.workerList(runId)[0]
    ?? storage.makeWorker(run, 'verification', asset, 'Async SSRF check', 'Promotion fixture')
  const canaryBroker = new CanaryBroker({ storage })
  const execution = new Execution(storage, { canaryBroker })
  t.after(() => execution.stop())

  const minted = canaryBroker.mintCanary(runId, 'engine:ssrf:url', origin, { storage, assignmentId: worker.id })
  canaryBroker.subscribe({
    runId,
    assignmentId: worker.id,
    canaryId: minted.id,
    token: minted.token,
    artifact: '',
    immediateMs: 0,
    windowMs: 120_000,
  })
  const carrier = storage.recordExchange({
    runId,
    assignmentId: worker.id,
    scopeRevision: storage.run(runId).scopeRevision,
    origin,
    finalOrigin: origin,
    redirectOrigins: [],
    method: 'POST',
    pathAndQuery: '/v1/integrations/webhook-test',
    personaHandle: null,
    status: 202,
    mediaType: 'application/json',
    reqHeaders: { 'content-type': 'application/json' },
    respHeaders: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: minted.httpUrl, note: 'queued for integration tester' }),
    durationMs: 7,
  })
  const recorded = canaryBroker.recordCallback({
    token: minted.token,
    callbackId: `cb-${randomUUID().slice(0, 8)}`,
    protocol: 'http',
    sourceIp: '127.0.0.1',
    method: 'GET',
    path: `/c/${minted.token}`,
    runId,
    assignmentId: worker.id,
    canaryId: minted.id,
  })
  assert.equal(recorded.accepted, true)

  await execution.drainPendingOob(runId, { graceMs: 0, pollMs: 1, sleep: async () => {} })

  const rows = storage.db.select().from((await import('../src/server/schema.ts')).findings).all()
    .filter(row => row.runId === runId && row.finding.cwe === 'CWE-918')
  assert.equal(rows.length, 1, 'exactly one receipt-confirmed SSRF finding')
  assert.equal(rows[0]!.finding.status, 'confirmed')
  assert.equal(rows[0]!.verificationTier, 'runtime_confirmed')
  assert.equal(rows[0]!.replaySpecId, null, 'a receipt-only finding keeps replay_spec_id null')
  assert.ok(rows[0]!.finding.exchangeIds?.includes(carrier.id))
  assert.match(rows[0]!.finding.verification ?? '', /ProofReceipt/)
})

test('M0: a promotion without a carrying exchange or for a non-probe canary never becomes a finding', async (t) => {
  const storage = makeStore(t)
  const origin = 'http://127.0.0.1:7778'
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 2 })
  const run = storage.run(runId)
  storage.updateRun(runId, { status: 'running', phase: 'verification' })
  const asset = run.candidates[0]!
  const worker = storage.workerList(runId)[0]
    ?? storage.makeWorker(run, 'verification', asset, 'Async SSRF negative', 'Promotion fixture')
  const canaryBroker = new CanaryBroker({ storage })
  const execution = new Execution(storage, { canaryBroker })
  t.after(() => execution.stop())

  // 1. Probe canary whose callback is delivered, but no recorded request ever carried the URL.
  const uncarried = canaryBroker.mintCanary(runId, 'engine:ssrf:url', origin, { storage, assignmentId: worker.id })
  canaryBroker.subscribe({ runId, assignmentId: worker.id, canaryId: uncarried.id, token: uncarried.token, artifact: '', immediateMs: 0, windowMs: 60_000 })
  canaryBroker.recordCallback({ token: uncarried.token, callbackId: `cb-${randomUUID().slice(0, 8)}`, protocol: 'http', sourceIp: '127.0.0.1', method: 'GET', path: `/c/${uncarried.token}`, runId, assignmentId: worker.id, canaryId: uncarried.id })

  // 2. A JWT/JKU canary is not an async-injection proof even with a carrying exchange.
  const jku = canaryBroker.mintCanary(runId, 'jwt-jku', origin, { storage, assignmentId: worker.id })
  canaryBroker.subscribe({ runId, assignmentId: worker.id, canaryId: jku.id, token: jku.token, artifact: '', immediateMs: 0, windowMs: 60_000 })
  storage.recordExchange({
    runId,
    assignmentId: worker.id,
    scopeRevision: storage.run(runId).scopeRevision,
    origin,
    finalOrigin: origin,
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery: `/jwks?u=${encodeURIComponent(jku.httpUrl)}`,
    personaHandle: null,
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: {},
    body: JSON.stringify({ keys: [] }),
    durationMs: 3,
  })
  canaryBroker.recordCallback({ token: jku.token, callbackId: `cb-${randomUUID().slice(0, 8)}`, protocol: 'http', sourceIp: '127.0.0.1', method: 'GET', path: `/c/${jku.token}`, runId, assignmentId: worker.id, canaryId: jku.id })

  await execution.drainPendingOob(runId, { graceMs: 0, pollMs: 1, sleep: async () => {} })

  const rows = storage.db.select().from((await import('../src/server/schema.ts')).findings).all()
    .filter(row => row.runId === runId && row.finding.cwe === 'CWE-918')
  assert.equal(rows.length, 0)
})
