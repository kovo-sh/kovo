/**
 * Cut 3c/3d prep — redirect, browser-sink and injection-fingerprint recipes, plus the SQL spec
 * envelope emission that lets the retest path run the typed `boolean_or_timing` recipe.
 *
 * No Docker: recipes are driven through fake Layer-1 deps; the spec emission is a pure function.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import {
  cut3FloorRecipe,
  runCut3Recipe,
  type FloorExchange,
  type FloorRecipeDeps,
  type FloorRequestSpec,
} from '../src/server/floor-recipes.ts'
import { synthSqlBoolean, synthSqlTime } from '../scripts/benchmark-specs-sql.ts'
import type { HypothesisOutcome, ProbeEnv } from '../scripts/benchmark-probes.ts'

// Floor recipes run in the local lab; the receipt schema accepts loopback only with that flag.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const origin = 'http://127.0.0.1:4300'
const actor = { handle: 'owner', role: 'member' as const, tenant: 'store-a' }

interface Reply {
  status: number
  body?: string
  json?: unknown
  location?: string
}

function depsFor(handler: (spec: FloorRequestSpec) => Reply, extra: Partial<FloorRecipeDeps> = {}): FloorRecipeDeps {
  let counter = 0
  return {
    request: (spec): FloorExchange => {
      const reply = handler(spec)
      counter += 1
      return {
        exchangeId: `x-${counter}`,
        status: reply.status,
        ...(reply.json !== undefined ? { json: reply.json } : {}),
        ...(reply.body !== undefined ? { body: reply.body } : {}),
        ...(reply.location ? { responseHeaders: { location: reply.location } } : {}),
        durationMs: 10,
      }
    },
    ...extra,
  }
}

// ---------------------------------------------------------------------------
// redirect
// ---------------------------------------------------------------------------

describe('cut3cd: redirect recipe', () => {
  const args = {
    origin,
    method: 'GET',
    pathAndQuery: '/login?next=/dashboard',
    vulnClass: 'open_redirect',
    actor,
  }

  test('confirms an off-origin Location that no control reaches', async () => {
    const execution = await runCut3Recipe(
      cut3FloorRecipe('redirect', { ...args, controlPathAndQuery: '/login?next=/dashboard', probePathAndQuery: '/login?next=https://evil.example/x' }),
      depsFor(spec => spec.pathAndQuery.includes('evil.example')
        ? { status: 302, location: 'https://evil.example/x' }
        : { status: 302, location: '/dashboard' }),
    )
    assert.equal(execution.result.confirmed, true, execution.result.verification.reason)
    assert.equal(execution.result.verification.rule, 'redirect')
  })

  test('rejects a 3xx without a Location header', async () => {
    const execution = await runCut3Recipe(
      cut3FloorRecipe('redirect', args),
      depsFor(() => ({ status: 302 })),
    )
    assert.equal(execution.result.confirmed, false)
    assert.ok(execution.failure?.missingRoles.includes('redirect_probe'), JSON.stringify(execution.failure))
  })

  test('rejects when the control redirects to the same destination', async () => {
    const execution = await runCut3Recipe(
      cut3FloorRecipe('redirect', args),
      depsFor(() => ({ status: 302, location: 'https://evil.example/x' })),
    )
    assert.equal(execution.result.confirmed, false)
  })

  test('rejects an on-origin Location', async () => {
    const execution = await runCut3Recipe(
      cut3FloorRecipe('redirect', args),
      depsFor(spec => spec.pathAndQuery.includes('next=/dashboard')
        ? { status: 302, location: '/dashboard' }
        : { status: 302, location: `${origin}/dashboard` }),
    )
    assert.equal(execution.result.confirmed, false)
  })
})

// ---------------------------------------------------------------------------
// browser sink
// ---------------------------------------------------------------------------

describe('cut3cd: browser_sink recipe', () => {
  const args = {
    origin,
    method: 'GET',
    pathAndQuery: '/portal',
    vulnClass: 'dom_xss',
    actor,
  }

  test('confirms when the host trace recorded a sink', async () => {
    const execution = await runCut3Recipe(
      cut3FloorRecipe('browser_sink', { ...args, expectSinks: ['dom_xss'] }),
      depsFor(() => ({ status: 200 }), { browserTrace: () => ({ id: 'trace-1', origin, sinks: ['dom_xss', 'storage_write'] }) }),
    )
    assert.equal(execution.result.confirmed, true, execution.result.verification.reason)
    assert.equal(execution.result.verification.rule, 'browser')
    assert.deepEqual(execution.receipt.browserTraceIds, ['trace-1'])
  })

  test('fails closed when the host recorded no trace', async () => {
    const execution = await runCut3Recipe(cut3FloorRecipe('browser_sink', args), depsFor(() => ({ status: 200 })))
    assert.equal(execution.result.confirmed, false)
    assert.ok(execution.failure?.missingRoles.includes('browser_trace'), JSON.stringify(execution.failure))
  })

  test('rejects a trace with no sink and an unexpected sink', async () => {
    const empty = await runCut3Recipe(
      cut3FloorRecipe('browser_sink', args),
      depsFor(() => ({ status: 200 }), { browserTrace: () => ({ id: 'trace-2', origin, sinks: [] }) }),
    )
    assert.equal(empty.result.confirmed, false)
    const mismatched = await runCut3Recipe(
      cut3FloorRecipe('browser_sink', { ...args, expectSinks: ['dom_xss'] }),
      depsFor(() => ({ status: 200 }), { browserTrace: () => ({ id: 'trace-3', origin, sinks: ['storage_write'] }) }),
    )
    assert.equal(mismatched.result.confirmed, false)
  })
})

// ---------------------------------------------------------------------------
// injection fingerprint
// ---------------------------------------------------------------------------

describe('cut3cd: injection_fingerprint recipe', () => {
  const args = {
    origin,
    method: 'GET',
    pathAndQuery: '/search?q=widgets',
    vulnClass: 'injection',
    actor,
    param: 'q',
    payload: "widgets'",
    family: 'sqli' as const,
  }

  test('confirms on a probe-only engine fingerprint', async () => {
    const execution = await runCut3Recipe(
      cut3FloorRecipe('injection_fingerprint', args),
      depsFor(spec => decodeURIComponent(spec.pathAndQuery).endsWith("q=widgets'")
        ? { status: 500, body: 'SQLITE_ERROR: near "widgets": syntax error' }
        : { status: 200, body: '{"results":[]}' }),
    )
    assert.equal(execution.result.confirmed, true, execution.result.verification.reason)
    assert.equal(execution.result.verification.rule, 'impact')
  })

  test('rejects a bare status change with no fingerprint', async () => {
    const execution = await runCut3Recipe(
      cut3FloorRecipe('injection_fingerprint', args),
      depsFor(spec => decodeURIComponent(spec.pathAndQuery).endsWith("q=widgets'")
        ? { status: 500, body: 'Internal Server Error' }
        : { status: 200, body: '{"results":[]}' }),
    )
    assert.equal(execution.result.confirmed, false)
    assert.ok(execution.failure?.missingRoles.includes('injection_probe'), JSON.stringify(execution.failure))
  })

  test('rejects when the benign control produces the same engine error', async () => {
    const execution = await runCut3Recipe(
      cut3FloorRecipe('injection_fingerprint', args),
      depsFor(() => ({ status: 500, body: 'SQLITE_ERROR: no such table: users' })),
    )
    assert.equal(execution.result.confirmed, false)
  })
})

// ---------------------------------------------------------------------------
// SQL spec → boolean_or_timing envelope
// ---------------------------------------------------------------------------

function fakeOutcome(anomalies: Array<Record<string, unknown>>): HypothesisOutcome {
  return {
    hyp: {
      endpoint: { origin, path: '/search?q=widgets', method: 'GET', params: [{ name: 'q', location: 'query', required: false }] },
      method: 'GET',
      path: '/search?q=widgets',
      param: { name: 'q', location: 'query' },
      location: 'query',
    },
    verdict: 'signal',
    anomalies,
    details: {},
    csrfRejected: false,
    contextReset: false,
    tierBlocked: false,
    requests: 4,
    ctx: { baseline: 'widgets' },
  } as unknown as HypothesisOutcome
}

const fakeEnv = {
  origin,
  owner: 'owner',
  caps: { sessionAndCsrf: false },
  session: 'sess',
} as unknown as ProbeEnv

describe('cut3cd: SQL spec envelope emission', () => {
  test('a boolean hit carries a boolean mode envelope with concrete arms', () => {
    const specs = synthSqlBoolean(fakeOutcome([{ type: 'boolean_differential', style: 'single_quote', baselineValue: 'widgets' }]), fakeEnv)
    assert.equal(specs.length, 1)
    const recipe = (specs[0]!.spec as { recipe?: { recipeId: string; args: Record<string, unknown> } }).recipe
    assert.ok(recipe, 'expected a recipe envelope')
    assert.equal(recipe!.recipeId, 'boolean_or_timing')
    assert.equal(recipe!.args.mode, 'boolean')
    assert.match(String(recipe!.args.controlPathAndQuery), /q=widgets/)
    assert.match(String(recipe!.args.probePathAndQuery), /1%3D1|1=1/)
  })

  test('an error-fingerprint spec carries a status mode envelope', () => {
    const specs = synthSqlBoolean(fakeOutcome([{ type: 'db_error_fingerprint', dialect: 'sqlite' }]), fakeEnv)
    assert.ok(specs.length >= 1)
    const recipe = (specs[0]!.spec as { recipe?: { args: Record<string, unknown> } }).recipe
    assert.ok(recipe, 'expected a recipe envelope on the primary fingerprint spec')
    assert.equal(recipe!.args.mode, 'status')
    assert.ok(recipe!.args.contradictionPathAndQuery, 'status mode needs the contradiction arm')
  })

  test('a timing hit carries a timing mode envelope', () => {
    const specs = synthSqlTime(fakeOutcome([{
      type: 'sql_time_differential',
      style: 'single_quote',
      dialect: 'sqlite',
      delayMs: 1500,
      baselineValue: 'widgets',
    }]), fakeEnv)
    assert.equal(specs.length, 1)
    const recipe = (specs[0]!.spec as { recipe?: { args: Record<string, unknown> } }).recipe
    assert.ok(recipe, 'expected a recipe envelope')
    assert.equal(recipe!.args.mode, 'timing')
    assert.ok(recipe!.args.controlPathAndQuery)
    assert.ok(recipe!.args.probePathAndQuery)
  })
})

// ---------------------------------------------------------------------------
// Cut 3d: conserved_balance (race_burst retirement)
// ---------------------------------------------------------------------------

interface ConservedState { balance: number }

function conservedDeps(state: ConservedState, racy: boolean): FloorRecipeDeps {
  let counter = 0
  const reply = (status: number, json: unknown): FloorExchange => ({
    exchangeId: `cb-${++counter}`,
    status,
    json,
    body: JSON.stringify(json),
    durationMs: 5,
  })
  return {
    request: (spec: FloorRequestSpec): FloorExchange => {
      const amount = Number((spec.jsonBody as { amount?: number } | undefined)?.amount ?? 0)
      if (spec.role.includes('read') || amount === 0) return reply(200, { balance: state.balance })
      if (state.balance < amount) return reply(409, { error: 'insufficient' })
      state.balance -= amount
      return reply(200, { balance: state.balance, redeemed: amount })
    },
    burst: (specs: readonly FloorRequestSpec[]): FloorExchange[] => {
      const amount = Number((specs[0]?.jsonBody as { amount?: number } | undefined)?.amount ?? 0)
      // A racy service acknowledges every request but debits once; a correct one debits each.
      state.balance -= racy ? amount : amount * specs.length
      const shared = state.balance + (racy ? amount * (specs.length - 1) : 0)
      return specs.map(() => reply(200, { balance: shared, redeemed: amount }))
    },
  }
}

const conservedArgs = {
  origin,
  method: 'POST',
  pathAndQuery: '/giftcards/1/redeem',
  vulnClass: 'race_double_spend',
  actor,
  body: { amount: 4 },
  burst: 4,
  readback: { method: 'POST', pathAndQuery: '/giftcards/1/redeem', jsonBody: { amount: 0 } },
  balanceField: 'balance',
  unitDebit: 4,
} as const

describe('cut3cd: conserved_balance recipe', () => {
  test('confirms a double-spend where four acknowledgements debit the conserved value once', async () => {
    const state: ConservedState = { balance: 100 }
    const execution = await runCut3Recipe(cut3FloorRecipe('conserved_balance', { ...conservedArgs }), conservedDeps(state, true))
    assert.equal(execution.result.confirmed, true, execution.result.verification.reason)
    assert.equal(execution.result.verification.rule, 'conserved_balance')
    assert.equal(execution.receipt.vulnClass, 'race_double_spend')
  })

  test('dismisses a correct service that debits every acknowledged request', async () => {
    const state: ConservedState = { balance: 100 }
    const execution = await runCut3Recipe(cut3FloorRecipe('conserved_balance', { ...conservedArgs }), conservedDeps(state, false))
    assert.equal(execution.result.confirmed, false)
    assert.equal(execution.result.verification.rule, 'conserved_balance')
    assert.equal(execution.failure?.code, 'receipt_rejected')
    assert.match(String(execution.result.verification.reason), /no conservation violation|under-debit/i)
  })

  test('fails closed without a serial control readback', async () => {
    const state: ConservedState = { balance: 100 }
    const deps = conservedDeps(state, true)
    // Remove the serial control's post-read by failing the serial mutation instead.
    const failing: FloorRecipeDeps = {
      ...deps,
      request: (spec: FloorRequestSpec) => {
        if (spec.role === 'serial_control_1') return { exchangeId: 'cb-fail', status: 500, json: { error: 'boom' }, body: '{}', durationMs: 5 }
        return deps.request(spec)
      },
    }
    const execution = await runCut3Recipe(cut3FloorRecipe('conserved_balance', { ...conservedArgs }), failing)
    assert.equal(execution.result.confirmed, false)
  })
})
