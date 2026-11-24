/**
 * v7 M0 Cut 3a — strict-strangler wiring tests.
 *
 * These exercise the *production* recipe path end to end: the planner derives recipe arguments from
 * a floor hypothesis + differential probe, the broker adapter issues the exchanges, `verifyReceipt`
 * decides, and the recorded spec/result match the shape the finding pipeline persists.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import {
  assertNotRecipeWiredLegacyCall,
  RecipeWiredLegacyCallError,
} from '../src/server/replay-verifier.ts'
import {
  planFloorRecipe,
  recipeSpecRecord,
  recipeVerificationResult,
  runPlannedRecipe,
} from '../src/server/floor-recipe-engine.ts'
import { wiredRecipeForSpecKind } from '../src/server/floor-recipes.ts'
import type { EngineHypothesis } from '../src/server/deterministic-specs.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from '../src/server/broker.ts'

const ORIGIN = 'https://app.example.invalid'

interface FakeReply {
  status: number
  body: string
  mediaType?: string
  durationMs?: number
}

class FakeBroker {
  readonly requests: BrokerHttpRequest[] = []
  private index = 0
  readonly exchanges: BrokerExchangeResult[] = []
  private readonly reply: (req: BrokerHttpRequest, index: number) => FakeReply

  constructor(reply: (req: BrokerHttpRequest, index: number) => FakeReply) {
    this.reply = reply
  }

  async executeHttp(req: BrokerHttpRequest): Promise<BrokerExchangeResult> {
    this.requests.push(req)
    const reply = this.reply(req, this.index++)
    const exchange = {
      origin: req.origin,
      finalOrigin: req.origin,
      redirectOrigins: [],
      method: req.method,
      pathAndQuery: req.pathAndQuery,
      personaHandle: req.persona ?? null,
      status: reply.status,
      mediaType: reply.mediaType ?? 'application/json',
      reqHeaders: req.headers ?? {},
      respHeaders: { 'content-type': reply.mediaType ?? 'application/json' },
      setCookies: [],
      bodyPreview: reply.body.slice(0, 256),
      body: reply.body,
      bodySha256: String(this.requests.length),
      bodyBytes: reply.body.length,
      bodyTruncated: false,
      durationMs: reply.durationMs ?? 5,
      observation: {},
    } as unknown as BrokerExchangeResult
    this.exchanges.push(exchange)
    return exchange
  }
}

const grant = {} as Grant
const signal = new AbortController().signal

function booleanHypothesis(): EngineHypothesis {
  return {
    key: 'sqli:1',
    endpoint: { id: 'ep-1', origin: ORIGIN, method: 'GET', pathTemplate: '/search?q=', params: [] },
    probeClass: 'sqli_boolean',
    intent: 'sqli',
    method: 'GET',
    pathAndQuery: '/search?q=',
    param: { name: 'q', location: 'query' },
    baselineValue: '1',
    risk: 60,
  }
}

function booleanProbe(): DifferentialResult {
  return {
    probeClass: 'sqli_boolean',
    origin: ORIGIN,
    pathAndQuery: '/search?q=',
    verdict: 'signal',
    summary: 'boolean differential',
    anomalies: [{ type: 'boolean_differential', style: 'numeric' }],
    details: {},
    requestsSent: 6,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 1,
  }
}

function raceHypothesis(): EngineHypothesis {
  return {
    key: 'race:1',
    endpoint: { id: 'ep-2', origin: ORIGIN, method: 'POST', pathTemplate: '/api/credit/redeem', params: [] },
    probeClass: 'workflow_invariant',
    intent: 'race',
    method: 'POST',
    pathAndQuery: '/api/credit/redeem',
    ownerPersona: 'acme_owner',
    jsonBody: { amount: 100 },
    raceBurst: true,
    risk: 80,
  }
}

function raceProbe(): DifferentialResult {
  return {
    probeClass: 'workflow_invariant',
    origin: ORIGIN,
    pathAndQuery: '/api/credit/redeem',
    verdict: 'signal',
    summary: 'race double spend',
    anomalies: [{
      type: 'race_double_spend',
      raceOrigin: ORIGIN,
      path: '/api/credit/redeem',
      amountField: 'amount',
      balanceField: 'balance',
      transferredField: 'transferred',
      amount: 100,
      burstSize: 3,
      idempotencyKey: 'race-key-1',
    }],
    details: {},
    requestsSent: 5,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 1,
  }
}

function personas() {
  return [{ handle: 'acme_owner', roleLabel: 'owner (acme)', privilege: 'admin' as const, tenant: 'acme' }]
}

// ============================================================================
// Boolean SQLi: recipe plan → broker → receipt
// ============================================================================

function booleanBroker(app: 'vulnerable' | 'hardened'): { broker: FakeBroker } {
  const broker = new FakeBroker(req => {
    const q = new URL(req.pathAndQuery, ORIGIN).searchParams.get('q') ?? ''
    if (app === 'hardened') {
      return { status: 200, body: JSON.stringify({ rows: [{ id: 1 }], message: 'ok' }) }
    }
    const match = /AND\s+(\d+)\s*=\s*(\d+)/.exec(q)
    const rows = match && match[1] !== match[2] ? [] : [{ id: 1 }, { id: 2 }]
    return { status: 200, body: JSON.stringify({ rows, message: 'ok' }) }
  })
  return { broker }
}

test('recipe-wired sql_boolean_diff confirms a vulnerable paired differential through the broker', async () => {
  const fake = booleanBroker('vulnerable')
  const plan = planFloorRecipe({
    hypothesis: booleanHypothesis(),
    probe: booleanProbe(),
    specKind: 'sql_boolean_diff',
    vulnClass: 'sqli',
    personas: [],
  })
  assert.ok(plan, 'sql_boolean_diff must be wired')
  assert.equal(plan.recipeId, 'boolean_or_timing')
  assert.equal(plan.skipReason, undefined)

  const exchangeIds = ['ex-1', 'ex-2', 'ex-3', 'ex-4']
  let cursor = 0
  const execution = await runPlannedRecipe({
    plan,
    hypothesis: booleanHypothesis(),
    broker: fake.broker as unknown as RequestBroker,
    grant,
    signal,
    recordExchange: () => exchangeIds[cursor++] ?? `ex-${cursor}`,
  })

  assert.equal(execution.result.confirmed, true, execution.failure?.message ?? 'unexpected rejection')
  assert.equal(execution.result.verification.rule, 'boolean')
  assert.deepEqual(execution.result.exchangeIds, exchangeIds)
  assert.equal(execution.receipt.exchangeIds.length, 4)
  // Same instrumentation as a probe: origin, probe class, JSON accept, and a paired round each way.
  assert.ok(fake.broker.requests.every(request => request.origin === ORIGIN))
  assert.ok(fake.broker.requests.every(request => request.probeClass === 'sqli_boolean'))
  assert.equal(fake.broker.requests.length, 4)

  const record = recipeSpecRecord(plan, execution)
  const parsed = declarativeReplaySpecSchema.safeParse(record.spec)
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues))

  const result = recipeVerificationResult(plan, execution, execution.result.exchangeIds)
  assert.equal(result.verdict, 'confirmed')
  assert.equal(result.verificationTier, 'runtime_confirmed')
  assert.equal(result.receipt?.mode, 'strict')
  assert.deepEqual(result.exchangeIds, exchangeIds)
  assert.equal(result.outcome.confirmed, true)
  assert.match(String(result.evidenceSha256), /^[0-9a-f]{64}$/)
})

test('recipe-wired sql_boolean_diff rejects the hardened fixture with a named missing role', async () => {
  const fake = booleanBroker('hardened')
  const plan = planFloorRecipe({
    hypothesis: booleanHypothesis(),
    probe: booleanProbe(),
    specKind: 'sql_boolean_diff',
    vulnClass: 'sqli',
    personas: [],
  })
  assert.ok(plan)
  const execution = await runPlannedRecipe({
    plan,
    hypothesis: booleanHypothesis(),
    broker: fake.broker as unknown as RequestBroker,
    grant,
    signal,
    recordExchange: (() => { let n = 0; return () => `hx-${++n}` })(),
  })
  assert.equal(execution.result.confirmed, false)
  assert.equal(execution.failure?.code, 'receipt_rejected')
  assert.ok(execution.failure!.missingRoles.includes('structural_delta'), execution.failure!.missingRoles.join(','))
})

test('recipe-wired boolean receipts are byte-identical across runs on identical evidence', async () => {
  const runOnce = async () => {
    const fake = booleanBroker('vulnerable')
    const plan = planFloorRecipe({
      hypothesis: booleanHypothesis(),
      probe: booleanProbe(),
      specKind: 'sql_boolean_diff',
      vulnClass: 'sqli',
      personas: [],
    })!
    let cursor = 0
    const execution = await runPlannedRecipe({
      plan,
      hypothesis: booleanHypothesis(),
      broker: fake.broker as unknown as RequestBroker,
      grant,
      signal,
      recordExchange: () => `ex-${++cursor}`,
    })
    return {
      receipt: execution.receipt,
      transcript: execution.result.transcript,
      verification: execution.result.verification,
      record: recipeSpecRecord(plan, execution).spec,
    }
  }
  const first = await runOnce()
  const second = await runOnce()
  assert.equal(JSON.stringify(first), JSON.stringify(second))
})

// ============================================================================
// No-fallback assertion + explicit legacy path for unmapped kinds
// ============================================================================

test('the no-fallback assertion throws for every wired pair and stays quiet for unmapped kinds', () => {
  for (const [kind, vulnClass] of [['sql_boolean_diff', 'sqli']] as const) {
    assert.equal(wiredRecipeForSpecKind(kind, vulnClass) !== null, true, `${kind} must be wired`)
    assert.throws(
      () => assertNotRecipeWiredLegacyCall({ kind, category: vulnClass }),
      (error: unknown) => error instanceof RecipeWiredLegacyCallError
        && error.code === 'GUARDIAN_RECIPE_WIRED_LEGACY_CALL'
        && error.specKind === kind,
    )
  }
  for (const [kind, category] of [
    ['http_chain', 'path_traversal'],
    ['http_chain', 'open_redirect'],
    ['http_chain', 'xss_reflected'],
    ['http_chain', 'info_disclosure'],
    ['http_chain', 'bola'],
    ['http_chain', 'bfla'],
    ['http_chain', 'cross_tenant_write'],
    ['race_burst', 'race_double_spend'],
    ['sql_time_diff', 'sqli'],
    ['browser_chain', 'xss_reflected'],
    ['rce_proof', 'ssti'],
  ] as const) {
    assert.equal(wiredRecipeForSpecKind(kind, category), null, `${kind}/${category} must stay legacy`)
    assert.doesNotThrow(() => assertNotRecipeWiredLegacyCall({ kind, category }))
  }
})

test('unmapped families still synthesize legacy specs and never get a recipe plan', () => {
  const probe = booleanProbe()
  for (const [specKind, vulnClass] of [
    ['http_chain', 'bola'],
    ['http_chain', 'bfla'],
    ['http_chain', 'cross_tenant_write'],
    ['http_chain', 'mass_assignment'],
    ['http_chain', 'info_disclosure'],
    ['http_chain', 'xxe'],
    ['http_chain', 'path_traversal'],
    ['race_burst', 'race_double_spend'],
    ['sql_time_diff', 'sqli'],
  ] as const) {
    assert.equal(planFloorRecipe({
      hypothesis: booleanHypothesis(),
      probe,
      specKind,
      vulnClass,
      personas: [],
    }), null, `${specKind}/${vulnClass} must stay on the legacy path`)
  }
})
