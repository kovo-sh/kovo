process.env.GUARDIAN_ALLOW_LOCAL_LAB ??= '1'
/**
 * v5.1 — Tier-3 approval consumption contract for the ReplayVerifier.
 *
 * The verifier's pre-execution gate must reproduce the exact single-use fingerprint a Tier-3
 * decision registered (origin/method/path/persona/body hash/flags). An approval without context can
 * never be consumed; a matching operator endpoint pattern must never authorize an RCE/upload proof.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { test } from 'node:test'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { authorizeStateChange, StateChangeApprovalLedger } from '../src/server/approval-judge.ts'
import type { StateChangeApprovalContext } from '../src/server/approval-judge.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant } from '../src/server/broker.ts'
import { verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import type { ApprovedEndpointPattern } from '../src/domain.ts'

const RUN_ID = 'run-approvals'
const SCOPE_REVISION = 11

async function fixture(handler: (req: IncomingMessage, res: ServerResponse) => unknown) {
  const requests: string[] = []
  const server = createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`)
    void handler(req, res)
  }).listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fixture has no port')
  return {
    origin: `http://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }),
  }
}

interface ApprovalHarness {
  ledger: StateChangeApprovalLedger
  contexts: Array<StateChangeApprovalContext | undefined>
  grant: (origin: string, patterns?: ApprovedEndpointPattern[], overrides?: Partial<Grant>) => Grant
}

/** Mirrors `Execution.buildGrant`: exact one-shot ledger + optional operator patterns. */
function approvalHarness(): ApprovalHarness {
  const ledger = new StateChangeApprovalLedger()
  const contexts: Array<StateChangeApprovalContext | undefined> = []
  return {
    ledger,
    contexts,
    grant: (origin: string, patterns: ApprovedEndpointPattern[] = [], overrides: Partial<Grant> = {}): Grant => ({
      origin,
      tier: 3,
      allowLocalLab: true,
      maxRpsPerOrigin: 100,
      scopeRevision: SCOPE_REVISION,
      personas: new Map(),
      canRead: candidate => candidate === origin,
      audit: () => undefined,
      ...overrides,
      isStateChangeApproved: (origin, method, pathAndQuery, context) => {
        contexts.push(context)
        return authorizeStateChange({
          runId: RUN_ID,
          origin,
          method,
          pathAndQuery,
          scopeRevision: SCOPE_REVISION,
          context,
          approvedPatterns: patterns,
          ledger,
        }).approved
      },
    }),
  }
}

function baseFields(origin: string) {
  return {
    version: 1 as const,
    origin,
    title: 'Tier 3 replay approval contract',
    category: 'injection-input',
    cwe: 'CWE-94',
    severity: 'high' as const,
    severityRationale: 'Deterministic proof of execution.',
    impact: 'Remote code execution proof of concept.',
    remediation: 'Eliminate dynamic evaluation.',
    recheckInstructions: 'Replay the control and probe.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "proof", expected: "no execution" }',
  }
}

async function verify(spec: Record<string, unknown>, grant: Grant) {
  const parsed = declarativeReplaySpecSchema.safeParse(spec)
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues))
  return verifyReplaySpec({
    spec,
    broker: new RequestBroker({ rejectUnauthorized: false }),
    backend: new LocalJqBackend(),
    grant,
    signal: AbortSignal.timeout(30_000),
  })
}

function calcFixture() {
  return fixture((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const expr = url.searchParams.get('expr') ?? ''
    const match = /^(\d{1,6})\*(\d{1,6})$/.exec(expr)
    res.setHeader('Content-Type', 'text/plain')
    res.end(match ? String(Number(match[1]) * Number(match[2])) : 'invalid')
  })
}

function rceSpec(origin: string) {
  return {
    ...baseFields(origin),
    kind: 'rce_proof',
    proofMode: 'dynamic_math',
    controlStep: {
      id: 'c1', role: 'control', description: 'Static arithmetic control',
      request: { origin, method: 'GET', pathAndQuery: '/calc?expr=2*3' },
    },
    probeStep: {
      id: 'p1', role: 'probe', description: 'Dynamic nonce arithmetic probe',
      request: { origin, method: 'GET', pathAndQuery: '/calc?expr={{nonce_a}}*{{nonce_b}}' },
    },
  }
}

const RCE_PROBE_PATH = '/calc?expr={{nonce_a}}*{{nonce_b}}'

test('rce_proof: an exact Tier-3 approval is consumed once and the replay fails on replay', async () => {
  const fx = await calcFixture()
  try {
    const harness = approvalHarness()
    harness.ledger.grant({
      runId: RUN_ID,
      origin: fx.origin,
      method: 'GET',
      pathAndQuery: RCE_PROBE_PATH,
      scopeRevision: SCOPE_REVISION,
      personaHandle: null,
      bodyHash: null,
      hasMultipart: false,
      isRaceBurst: false,
      isRceProof: true,
    }, { expiresAt: Date.now() + 60_000 })

    const first = await verify(rceSpec(fx.origin), harness.grant(fx.origin))
    assert.equal(first.verdict, 'confirmed', String(first.outcome.reason))
    assert.ok(harness.contexts.length >= 1, 'the verifier must call the approval hook with context')
    assert.equal(harness.contexts[0]?.isRceProof, true, 'rce proofs must be flagged so patterns cannot authorize them')
    assert.equal(harness.contexts[0]?.personaHandle, null)
    assert.equal(harness.ledger.size, 0, 'the single-use grant must be consumed')

    const requestsAfterFirst = fx.requests.length
    const second = await verify(rceSpec(fx.origin), harness.grant(fx.origin))
    assert.equal(second.verdict, 'inconclusive')
    assert.match(second.outcome.reason ?? '', /requires explicit Tier 3 HITL operator approval/i)
    assert.equal(fx.requests.length, requestsAfterFirst, 'a replay without a fresh approval must send no wire requests')
  } finally { await fx.close() }
})

test('rce_proof: an operator endpoint pattern alone never authorizes the proof', async () => {
  const fx = await calcFixture()
  try {
    const harness = approvalHarness()
    const pattern: ApprovedEndpointPattern = { origin: fx.origin, method: 'GET', pathPattern: '/calc*', scopeRevision: SCOPE_REVISION }
    const res = await verify(rceSpec(fx.origin), harness.grant(fx.origin, [pattern]))
    assert.equal(res.verdict, 'inconclusive')
    assert.match(res.outcome.reason ?? '', /requires explicit Tier 3 HITL operator approval/i)
    assert.equal(fx.requests.length, 0, 'a pattern match must not send the rce proof')
  } finally { await fx.close() }
})

test('rce_proof: an approval registered for a different body does not authorize the replay', async () => {
  const fx = await calcFixture()
  try {
    const harness = approvalHarness()
    harness.ledger.grant({
      runId: RUN_ID,
      origin: fx.origin,
      method: 'GET',
      pathAndQuery: RCE_PROBE_PATH,
      scopeRevision: SCOPE_REVISION,
      personaHandle: null,
      body: '{"different":true}',
      hasMultipart: false,
      isRaceBurst: false,
      isRceProof: true,
    }, { expiresAt: Date.now() + 60_000 })
    const res = await verify(rceSpec(fx.origin), harness.grant(fx.origin))
    assert.equal(res.verdict, 'inconclusive')
    assert.equal(fx.requests.length, 0)
  } finally { await fx.close() }
})

function fakeExchange(req: BrokerHttpRequest, durationMs: number): BrokerExchangeResult {
  const body = '{"rows":[{"id":1}]}'
  return {
    origin: req.origin,
    finalOrigin: req.origin,
    redirectOrigins: [req.origin],
    method: req.method,
    pathAndQuery: req.pathAndQuery,
    personaHandle: req.persona ?? null,
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: { 'content-type': 'application/json' },
    setCookies: [],
    body,
    bodyPreview: body,
    bodySha256: createHash('sha256').update(body).digest('hex'),
    bodyBytes: Buffer.byteLength(body),
    bodyTruncated: false,
    durationMs,
    observation: {
      origin: req.origin,
      finalOrigin: req.origin,
      source: 'supplied observation',
      status: 200,
      mediaType: 'application/json',
      transportMaxAge: null,
      includeSubDomains: false,
    },
  }
}

/** Public-project replay: no local-lab bypass, deterministic timing without a real socket. */
function fakeTimingBroker() {
  let calls = 0
  const broker = {
    executeHttp: async (req: BrokerHttpRequest) => {
      calls += 1
      return fakeExchange(req, String(req.pathAndQuery).includes('pg_sleep') ? 1600 : 5)
    },
    getRegisteredSecrets: () => [],
  } as unknown as RequestBroker
  return { broker, calls: () => calls }
}

function timeSpec(origin: string) {
  return {
    ...baseFields(origin),
    kind: 'sql_time_diff',
    targetOrigin: origin,
    method: 'GET',
    pathAndQuery: '/time?q=1',
    paramName: 'q',
    paramLocation: 'query',
    baselineValue: '1',
    dialect: 'postgres',
    quoteStyle: 'single',
    delayMs: 1500,
    requiresTier3Approval: true,
  }
}

test('sql_time_diff: bare retired legacy spec fails closed without touching transport even with an approval', async () => {
  const origin = 'https://public.example.test'
  const harness = approvalHarness()
  const run = (broker: RequestBroker) => verifyReplaySpec({
    spec: timeSpec(origin),
    broker,
    backend: new LocalJqBackend(),
    grant: harness.grant(origin, [], { allowLocalLab: false }),
    signal: AbortSignal.timeout(30_000),
  })

  const unapprovedBroker = fakeTimingBroker()
  const unapproved = await run(unapprovedBroker.broker)
  assert.equal(unapproved.verdict, 'dismissed')
  assert.match(unapproved.outcome.reason ?? '', /retired_legacy_spec_kind/i)
  assert.equal(unapprovedBroker.calls(), 0)

  harness.ledger.grant({
    runId: RUN_ID,
    origin,
    method: 'GET',
    pathAndQuery: '/time?q=1',
    scopeRevision: SCOPE_REVISION,
    personaHandle: null,
    bodyHash: null,
    hasMultipart: false,
    isRaceBurst: false,
    isRceProof: false,
  }, { expiresAt: Date.now() + 60_000 })

  const approvedBroker = fakeTimingBroker()
  const approved = await run(approvedBroker.broker)
  assert.equal(approved.verdict, 'dismissed')
  assert.match(approved.outcome.reason ?? '', /retired_legacy_spec_kind/i)
  assert.equal(approvedBroker.calls(), 0)
})
