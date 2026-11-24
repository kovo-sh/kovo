/**
 * v7 Cut 3b parity — the two receipt primitives the spec VM still needed.
 *
 *   1. `status_differential`: the paired status-boolean triangle (benign 2xx baseline, 2xx
 *      tautology, <500 contradiction) with a contrast check. A single malformed 200 -> 500 is
 *      rejected, exactly like the legacy status-divergence branch.
 *   2. Authorization receipts: a bogus-id / peer denial control plus a pre-mutation readback and a
 *      separate post-GET delta, confirmed by the shared `assessImpactEvidence` authorization oracle
 *      (never a second copy of the rules).
 *
 * The tests also pin the planner wiring: object access maps to `access_boundary` (reads) or
 * `persisted_mutation` (writes), and the no-fallback assertion refuses the legacy DSL for every
 * wired pair.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { assertNotRecipeWiredLegacyCall, RecipeWiredLegacyCallError } from '../src/server/replay-verifier.ts'
import {
  planFloorRecipe,
  recipeSpecRecord,
  recipeVerificationResult,
  runPlannedRecipe,
} from '../src/server/floor-recipe-engine.ts'
import { floorRecipe, runFloorRecipe, wiredRecipeForSpecKind } from '../src/server/floor-recipes.ts'
import type { BooleanOrTimingArgs, AccessBoundaryArgs, PersistedMutationArgs } from '../src/server/floor-recipes.ts'
import { receiptRuleFor, verifyReceipt } from '../src/server/proof-receipt.ts'
import type { ImpactStep, ReceiptTranscript, ReceiptTranscriptEntry } from '../src/server/proof-receipt.ts'
import type { EngineHypothesis } from '../src/server/deterministic-specs.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from '../src/server/broker.ts'

const ORIGIN = 'https://app.example.invalid'
const grant = {} as Grant
const signal = new AbortController().signal

function step(partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: {
      handle: partial.actor?.handle ?? 'anon',
      role: partial.actor?.role ?? null,
      tenant: partial.actor?.tenant ?? null,
      auth: partial.actor?.auth ?? 'unknown',
      sameSite: null,
    },
    ...(partial.route !== undefined ? { route: partial.route } : {}),
    ...(partial.pathAndQuery !== undefined ? { pathAndQuery: partial.pathAndQuery } : {}),
    ...(partial.json !== undefined ? { json: partial.json } : {}),
    ...(partial.body !== undefined ? { body: partial.body } : {}),
    ...(partial.requestJson !== undefined ? { requestJson: partial.requestJson } : {}),
    ...(partial.requestHeaders !== undefined ? { requestHeaders: partial.requestHeaders } : {}),
    ...(partial.evidenceRole !== undefined ? { evidenceRole: partial.evidenceRole } : {}),
  }
}

function entry(exchangeId: string, s: ImpactStep, extra: Partial<ReceiptTranscriptEntry> = {}): ReceiptTranscriptEntry {
  return { exchangeId, step: s, ...extra }
}

// ============================================================================
// 1. status_differential receipt rule
// ============================================================================

type Triplet = { benign: Parameters<typeof step>[0]; tautology: Parameters<typeof step>[0]; contradiction: Parameters<typeof step>[0] }

function statusTriangle(options: {
  rounds?: number
  contradictionStatus?: number
  benignStatus?: number
  tautologyStatus?: number
  dropBenign?: boolean
  ids?: string[]
} = {}): { entries: ReceiptTranscriptEntry[]; exchangeIds: string[] } {
  const rounds = options.rounds ?? 2
  const ids = options.ids ?? Array.from({ length: rounds * 3 }, (_, index) => `sd-${index + 1}`)
  const entries: ReceiptTranscriptEntry[] = []
  const exchangeIds: string[] = []
  for (let round = 0; round < rounds; round += 1) {
    const arms: Triplet = {
      benign: {
        id: `b${round}`, arm: 'control', method: 'GET', status: options.benignStatus ?? 200,
        route: '/api/search',
        pathAndQuery: `/api/search?q=widget&k${round}=${round}`,
        body: JSON.stringify({ rows: [{ id: 1 }], message: 'ok' }),
        evidenceRole: 'benign_baseline',
      },
      tautology: {
        id: `t${round}`, arm: 'probe', method: 'GET', status: options.tautologyStatus ?? 200,
        route: '/api/search',
        pathAndQuery: `/api/search?q=${encodeURIComponent(`widget' AND 7919=7919-- -`)}&k${round}=${round}`,
        body: options.tautologyStatus && options.tautologyStatus >= 400
          ? '{"error":"invalid query"}'
          : JSON.stringify({ rows: [{ id: 1 }], message: 'ok' }),
        evidenceRole: 'tautology',
      },
      contradiction: {
        id: `c${round}`, arm: 'probe', method: 'GET', status: options.contradictionStatus ?? 400,
        route: '/api/search',
        pathAndQuery: `/api/search?q=${encodeURIComponent(`widget' AND 7919=7920-- -`)}&k${round}=${round}`,
        body: '{"error":"invalid query"}',
        evidenceRole: 'contradiction',
      },
    }
    for (const arm of [arms.benign, arms.tautology, arms.contradiction]) {
      if (options.dropBenign && arm.evidenceRole === 'benign_baseline') continue
      const id = ids[exchangeIds.length]!
      exchangeIds.push(id)
      entries.push(entry(id, step(arm)))
    }
  }
  return { entries, exchangeIds }
}

function statusReceipt(exchangeIds: readonly string[], vulnClass = 'sqli_status') {
  return {
    vulnClass,
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/search', param: 'q' },
    exchangeIds: [...exchangeIds],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'the tautology predicate kept the benign status while the contradiction predicate failed',
  }
}

test('status_differential confirms the benign/tautology/contradiction triangle across rounds', () => {
  assert.equal(receiptRuleFor('sqli_status').rule, 'status_differential')
  const triangle = statusTriangle()
  const result = verifyReceipt(statusReceipt(triangle.exchangeIds), { entries: triangle.entries })
  assert.equal(result.confirmed, true, result.reason)
  assert.equal(result.rule, 'status_differential')
  assert.match(result.reason, /benign baseline/)
})

test('status_differential rejects a single malformed 200 -> 500', () => {
  const single = statusTriangle({ rounds: 1, contradictionStatus: 500 })
  const result = verifyReceipt(statusReceipt(single.exchangeIds), { entries: single.entries })
  assert.equal(result.confirmed, false)
  assert.match(result.reason, /500|contradiction|2xx baseline|complete/i)
})

test('status_differential rejects a triangle with no benign baseline', () => {
  const triangle = statusTriangle({ dropBenign: true })
  const result = verifyReceipt(statusReceipt(triangle.exchangeIds), { entries: triangle.entries })
  assert.equal(result.confirmed, false)
})

test('status_differential rejects a 5xx contradiction even across rounds', () => {
  const triangle = statusTriangle({ contradictionStatus: 500 })
  const result = verifyReceipt(statusReceipt(triangle.exchangeIds), { entries: triangle.entries })
  assert.equal(result.confirmed, false)
})

test('status_differential rejects an unstable tautology/contradiction status pair', () => {
  const first = statusTriangle({ rounds: 1 })
  const second = statusTriangle({ rounds: 1, contradictionStatus: 422, ids: ['x2', 'x3', 'x4'] })
  const entries = [...first.entries, ...second.entries]
  const result = verifyReceipt(statusReceipt([...first.exchangeIds, ...second.exchangeIds]), { entries })
  assert.equal(result.confirmed, false)
  assert.match(result.reason, /unstable/i)
})

test('status_differential is not selectable by the structural sqli class', () => {
  assert.equal(receiptRuleFor('sqli').rule, 'boolean')
  assert.equal(receiptRuleFor('sqli_status').rule, 'status_differential')
})

// ============================================================================
// 2. Fake broker for recipe-level authorization proofs
// ============================================================================

interface FakeReply {
  status: number
  body: string
  mediaType?: string
}

class FakeBroker {
  readonly requests: BrokerHttpRequest[] = []
  readonly exchanges: BrokerExchangeResult[] = []
  private readonly reply: (req: BrokerHttpRequest, index: number) => FakeReply
  private index = 0

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
      durationMs: 5,
      observation: {},
    } as unknown as BrokerExchangeResult
    this.exchanges.push(exchange)
    return exchange
  }
}

function seq(): () => string {
  let n = 0
  return () => `ex-${++n}`
}

// ============================================================================
// 3. Authorization read: bogus-id denial + cross-actor disclosure
// ============================================================================

const READ_OWNER = { handle: 'persona_a', role: 'member' as const, tenant: 'tenant-a', auth: 'cookie' as const }
const READ_PROBE = { handle: 'persona_b', role: 'member' as const, tenant: 'tenant-b', auth: 'cookie' as const }

function readBroker(): FakeBroker {
  const victim = 'b893388c-def6-4ab3-9779-2b0fd5cf23f4'
  return new FakeBroker(req => {
    const match = /^\/api\/v1\/orders\/([^/?]+)$/.exec(req.pathAndQuery)
    const id = match?.[1] ?? ''
    if (id === 'order-victim' || id === victim) {
      return {
        status: 200,
        body: JSON.stringify({ id, owner_id: 'persona_a', tenant_id: 'tenant-a', total: 4200, email: 'victim@example.invalid' }),
      }
    }
    return { status: 404, body: '{"error":"not found"}' }
  })
}

test('access_boundary confirms a cross-actor read behind an authenticated bogus-id denial', async () => {
  const broker = readBroker()
  const args: AccessBoundaryArgs = {
    origin: ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/v1/orders/order-victim',
    vulnClass: 'bola',
    owner: READ_OWNER,
    probe: READ_PROBE,
    denied: READ_OWNER,
    deniedPathAndQuery: '/api/v1/orders/order-bogus',
  }
  const execution = await runFloorRecipe(floorRecipe('access_boundary', args), {
    request: req => ({
      status: req.pathAndQuery.includes('order-bogus') ? 404
        : req.pathAndQuery.includes('order-victim') ? 200 : 404,
      json: req.pathAndQuery.includes('order-victim')
        ? { id: 'order-victim', owner_id: 'persona_a', tenant_id: 'tenant-a', total: 4200, email: 'victim@example.invalid' }
        : undefined,
      body: req.pathAndQuery.includes('order-victim')
        ? JSON.stringify({ id: 'order-victim', owner_id: 'persona_a', tenant_id: 'tenant-a', total: 4200, email: 'victim@example.invalid' })
        : '{"error":"not found"}',
      route: req.pathAndQuery.split('?')[0],
    }),
    nextExchangeId: seq(),
  })
  assert.equal(execution.result.confirmed, true, execution.failure?.message ?? execution.result.verification.reason)
  assert.equal(execution.result.verification.rule, 'impact')
  assert.deepEqual(execution.result.transcript.entries?.map(item => item.evidenceRole), ['entitled_read', 'denied_control', 'probe_request'])
  // The recipe itself never decides: the shared oracle confirms the cross-tenant disclosure.
  assert.match(execution.result.verification.reason, /Cross-tenant|disclos/i)
})

test('access_boundary rejects the same cross-actor read when the probe gets no victim data', async () => {
  const execution = await runFloorRecipe(floorRecipe('access_boundary', {
    origin: ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/v1/orders/order-victim',
    vulnClass: 'bola',
    owner: READ_OWNER,
    probe: READ_PROBE,
    denied: READ_OWNER,
    deniedPathAndQuery: '/api/v1/orders/order-bogus',
  }), {
    request: req => ({
      status: req.pathAndQuery.includes('order-bogus') ? 404 : 200,
      json: req.pathAndQuery.includes('order-bogus') ? undefined : { ok: true },
      body: req.pathAndQuery.includes('order-bogus') ? '{"error":"not found"}' : '{"ok":true}',
      route: req.pathAndQuery.split('?')[0],
    }),
    nextExchangeId: seq(),
  })
  assert.equal(execution.result.confirmed, false)
})

// ============================================================================
// 4. Authorization write: baseline write + pre-read + mutation + post-read
// ============================================================================

const WRITE_OWNER = { handle: 'persona_a', role: 'member' as const, tenant: 'tenant-a', auth: 'cookie' as const }
const WRITE_PROBE = { handle: 'persona_b', role: 'member' as const, tenant: 'tenant-b', auth: 'cookie' as const }

function writeArgs(): PersistedMutationArgs {
  return {
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/v1/shipments/shipment-victim',
    vulnClass: 'cross_tenant_write',
    actor: WRITE_PROBE,
    body: { status: 'pending', external_id: 'ship-1' },
    baselineWrite: { body: { status: 'guardian-baseline', external_id: 'ship-1' }, actor: WRITE_OWNER, method: 'PATCH' },
    baselineMethod: 'GET',
    baselinePathAndQuery: '/api/v1/shipments',
    readbackMethod: 'GET',
    readbackPathAndQuery: '/api/v1/shipments',
    readbackActor: WRITE_OWNER,
  }
}

test('persisted_mutation confirms an authz write through a fresh baseline write and post-GET delta', async () => {
  let state = 'guardian-baseline'
  const execution = await runFloorRecipe(floorRecipe('persisted_mutation', writeArgs()), {
    request: req => {
      if (req.method === 'GET') {
        return {
          status: 200,
          json: { shipments: [{ id: 'shipment-victim', status: state }] },
          body: JSON.stringify({ shipments: [{ id: 'shipment-victim', status: state }] }),
          route: '/api/v1/shipments',
        }
      }
      const body = (req.jsonBody ?? {}) as { status?: string }
      state = body.status ?? state
      return { status: 204, body: '', route: '/api/v1/shipments/shipment-victim' }
    },
    nextExchangeId: seq(),
  })
  assert.equal(execution.result.confirmed, true, execution.failure?.message ?? execution.result.verification.reason)
  assert.equal(execution.result.verification.rule, 'impact')
  assert.deepEqual(execution.result.transcript.entries?.map(item => item.evidenceRole),
    ['baseline_write', 'baseline_read', 'mutation_probe', 'post_mutation_read'])
})

test('persisted_mutation rejects an idempotent authz write (identical post-get readback)', async () => {
  const execution = await runFloorRecipe(floorRecipe('persisted_mutation', {
    ...writeArgs(),
    baselineWrite: undefined,
  }), {
    request: req => {
      if (req.method === 'GET') {
        return {
          status: 200,
          json: { shipments: [{ id: 'shipment-victim', status: 'pending' }] },
          body: JSON.stringify({ shipments: [{ id: 'shipment-victim', status: 'pending' }] }),
          route: '/api/v1/shipments',
        }
      }
      return { status: 204, body: '', route: '/api/v1/shipments/shipment-victim' }
    },
    nextExchangeId: seq(),
  })
  assert.equal(execution.result.confirmed, false)
  assert.match(execution.failure?.message ?? '', /identical|delta|no.?op|persist/i)
})

test('persisted_mutation resets self-service state before the proof (bfla impersonation)', async () => {
  const sessions = new Map<string, string>()
  const execution = await runFloorRecipe(floorRecipe('persisted_mutation', {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/v1/admin/impersonate',
    vulnClass: 'bfla',
    actor: { handle: 'viewer', role: 'viewer', tenant: 'tenant-a', auth: 'cookie' },
    body: { store: 'target-store' },
    reset: { body: { store: 'own-store' }, actor: { handle: 'viewer', role: 'viewer', tenant: 'tenant-a', auth: 'cookie' }, method: 'POST' },
    baselineMethod: 'GET',
    baselinePathAndQuery: '/api/v1/session',
    readbackMethod: 'GET',
    readbackPathAndQuery: '/api/v1/session',
    readbackActor: { handle: 'viewer', role: 'viewer', tenant: 'tenant-a', auth: 'cookie' },
    requiredRole: 'admin',
    oracleEvents: ['privilege_escalation'],
  }), {
    request: req => {
      const persona = req.persona ?? 'viewer'
      if (req.method === 'GET') {
        const store = sessions.get(persona) ?? 'own-store'
        return {
          status: 200,
          json: { store, role: store === 'target-store' ? 'admin' : 'viewer' },
          body: JSON.stringify({ store, role: store === 'target-store' ? 'admin' : 'viewer' }),
          route: '/api/v1/session',
        }
      }
      const body = (req.jsonBody ?? {}) as { store?: string }
      sessions.set(persona, body.store ?? 'own-store')
      return { status: 200, body: '{"ok":true}', route: '/api/v1/admin/impersonate' }
    },
    nextExchangeId: seq(),
  })
  assert.equal(execution.result.confirmed, true, execution.failure?.message ?? execution.result.verification.reason)
  assert.match(execution.result.verification.reason, /role-gated function surface|persisted/i)
})

// ============================================================================
// 5. Planner wiring + no-fallback assertion
// ============================================================================

function authzHypothesis(read: boolean): EngineHypothesis {
  return {
    key: `authz:${read ? 'read' : 'write'}`,
    endpoint: { id: 'ep-authz', origin: ORIGIN, method: read ? 'GET' : 'PATCH', pathTemplate: read ? '/api/v1/orders/:orderId' : '/api/v1/shipments/:fulfillmentId', params: [] },
    probeClass: 'authz_matrix',
    intent: 'authz',
    method: read ? 'GET' : 'PATCH',
    pathAndQuery: read ? '/api/v1/orders/{{id}}' : '/api/v1/shipments/{{id}}',
    ownerPersona: 'persona_a',
    otherPersona: 'persona_b',
    resourceIds: ['b893388c-def6-4ab3-9779-2b0fd5cf23f4'],
    ...(read ? {} : { readbackPath: '/api/v1/shipments' }),
    risk: 60,
  }
}

function authzProbe(read: boolean): DifferentialResult {
  return {
    probeClass: 'authz_matrix',
    origin: ORIGIN,
    pathAndQuery: read ? '/api/v1/orders/{{id}}' : '/api/v1/shipments/{{id}}',
    verdict: 'signal',
    summary: 'unauthorized access',
    anomalies: [{
      type: 'unauthorized_access',
      method: read ? 'GET' : 'PATCH',
      resourceId: 'b893388c-def6-4ab3-9779-2b0fd5cf23f4',
      similarityToOwner: 0.95,
      ...(read ? {} : { bodyTemplate: { status: 'pending' } }),
    }],
    details: {},
    requestsSent: 6,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 1,
  }
}

function personas() {
  return [
    { handle: 'persona_a', roleLabel: 'member (tenant-a)', privilege: 'member' as const, tenant: 'tenant-a' },
    { handle: 'persona_b', roleLabel: 'member (tenant-b)', privilege: 'member' as const, tenant: 'tenant-b' },
  ]
}

test('authz reads plan the access_boundary recipe with a bogus-id denial control', () => {
  const plan = planFloorRecipe({
    hypothesis: authzHypothesis(true),
    probe: authzProbe(true),
    specKind: 'http_chain',
    vulnClass: 'bola',
    personas: personas(),
  })
  assert.ok(plan)
  assert.equal(plan.recipeId, 'access_boundary')
  const args = plan.args as AccessBoundaryArgs
  assert.equal(args.deniedPathAndQuery !== undefined, true)
  assert.notEqual(args.deniedPathAndQuery, args.pathAndQuery)
  assert.equal(args.owner.handle, 'persona_a')
  assert.equal(args.probe.handle, 'persona_b')
})

test('authz writes plan the persisted_mutation recipe with a pre-read/post-read delta', () => {
  const plan = planFloorRecipe({
    hypothesis: authzHypothesis(false),
    probe: authzProbe(false),
    specKind: 'http_chain',
    vulnClass: 'bola',
    personas: personas(),
  })
  assert.ok(plan)
  assert.equal(plan.recipeId, 'persisted_mutation')
  const args = plan.args as PersistedMutationArgs
  assert.equal(args.baselinePathAndQuery, '/api/v1/shipments')
  assert.equal(args.readbackPathAndQuery, '/api/v1/shipments')
  assert.equal(args.baselineWrite !== undefined, true)
  assert.equal(args.body.status, 'pending')
})

test('a planned authz read produces a schema-valid persisted http_chain spec', async () => {
  const plan = planFloorRecipe({
    hypothesis: authzHypothesis(true),
    probe: authzProbe(true),
    specKind: 'http_chain',
    vulnClass: 'bola',
    personas: personas(),
  })!
  const execution = await runPlannedRecipe({
    plan,
    hypothesis: authzHypothesis(true),
    broker: readBroker() as unknown as RequestBroker,
    grant,
    signal,
    recordExchange: seq(),
  })
  assert.equal(execution.result.confirmed, true, execution.failure?.message ?? execution.result.verification.reason)
  const record = recipeSpecRecord(plan, execution)
  const parsed = declarativeReplaySpecSchema.safeParse(record.spec)
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues))
  const result = recipeVerificationResult(plan, execution, execution.result.exchangeIds)
  assert.equal(result.verdict, 'confirmed')
  assert.equal(result.verificationTier, 'runtime_confirmed')
})

test('the no-fallback assertion refuses the legacy DSL for every wired authz pair', () => {
  for (const vulnClass of ['bola', 'idor', 'bfla', 'authorization', 'cross_tenant_read', 'cross_tenant_write']) {
    assert.equal(wiredRecipeForSpecKind('http_chain', vulnClass), 'access_boundary', `${vulnClass} must be wired`)
    assert.throws(
      () => assertNotRecipeWiredLegacyCall({ kind: 'http_chain', category: vulnClass }),
      (error: unknown) => error instanceof RecipeWiredLegacyCallError &&
        error.code === 'GUARDIAN_RECIPE_WIRED_LEGACY_CALL',
      `${vulnClass} must not reach verifyReplaySpec`,
    )
  }
  // Unmapped families stay legacy and stay silent.
  for (const [kind, category] of [
    ['http_chain', 'info_disclosure'],
    ['http_chain', 'mass_assignment'],
    ['http_chain', 'csrf'],
    ['http_chain', 'path_traversal'],
    ['http_chain', 'graphql_bola'],
    ['race_burst', 'race_double_spend'],
  ] as const) {
    assert.equal(wiredRecipeForSpecKind(kind, category), null)
    assert.doesNotThrow(() => assertNotRecipeWiredLegacyCall({ kind, category }))
  }
})

test('a wired status differential round-trips through the recipe surface', async () => {
  const args: BooleanOrTimingArgs = {
    origin: ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/search?q=widget',
    controlPathAndQuery: '/api/search?q=widget',
    probePathAndQuery: `/api/search?q=${encodeURIComponent("widget' AND 7919=7919-- -")}`,
    contradictionPathAndQuery: `/api/search?q=${encodeURIComponent("widget' AND 7919=7920-- -")}`,
    param: 'q',
    vulnClass: 'sqli',
    mode: 'status',
    rounds: 2,
  }
  const execution = await runFloorRecipe(floorRecipe('boolean_or_timing', args), {
    request: req => {
      const q = new URL(req.pathAndQuery, ORIGIN).searchParams.get('q') ?? ''
      if (!/AND/.test(q)) return { status: 200, body: JSON.stringify({ rows: [{ id: 1 }] }), route: '/api/search' }
      const match = /AND\s+(\d+)\s*=\s*(\d+)/.exec(q)
      const equal = match && match[1] === match[2]
      return equal
        ? { status: 200, body: JSON.stringify({ rows: [{ id: 1 }] }), route: '/api/search' }
        : { status: 400, body: '{"error":"invalid query"}', route: '/api/search' }
    },
    nextExchangeId: seq(),
  })
  assert.equal(execution.result.confirmed, true, execution.failure?.message ?? execution.result.verification.reason)
  assert.equal(execution.result.verification.rule, 'status_differential')
  assert.equal(execution.receipt.vulnClass, 'sqli_status')
  assert.equal(execution.result.exchangeIds.length, 6)
})
