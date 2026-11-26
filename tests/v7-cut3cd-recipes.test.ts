/**
 * Cut 3c/3d prep — redirect, browser-sink and injection-fingerprint recipes, plus the SQL spec
 * envelope emission that lets the retest path run the typed `boolean_or_timing` recipe.
 *
 * No Docker: recipes are driven through fake Layer-1 deps; the spec emission is a pure function.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import {
  browserSinkEnvelopeFromSteps,
  cut3FloorRecipe,
  isProtocolBrowserSpec,
  runCut3Recipe,
  wiredRecipeForSpecKind,
  type FloorExchange,
  type FloorRecipeDeps,
  type FloorRequestSpec,
} from '../src/server/floor-recipes.ts'
import { browserSessionSeam } from '../src/server/floor-recipe-engine.ts'
import type { ScopedBrowser } from '../src/server/scoped-browser.ts'
import { synthSqlBoolean, synthSqlTime } from '../scripts/benchmark-specs-sql.ts'
import type { HypothesisOutcome, ProbeEnv } from '../scripts/benchmark-probes.ts'

// Floor recipes run in the local lab; the receipt schema accepts loopback only with that flag.
process.env.KOVO_ALLOW_LOCAL_LAB = '1'

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
    runId: 'run-v7-cut3cd-recipes',
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
// Cut 3d: navigate/fill/click browser proofs run the browser_sink recipe
// ---------------------------------------------------------------------------

describe('cut3cd: browser_chain -> browser_sink envelope', () => {
  const domSteps = [
    { id: 'c1', role: 'control', description: 'control', origin, pathAndQuery: '/portal', action: 'navigate' },
    { id: 'p1', role: 'probe', description: 'fill', origin, pathAndQuery: '/portal', action: 'fill', selector: '#q', value: '{{canary_token}}' },
    { id: 'p2', role: 'probe', description: 'click', origin, pathAndQuery: '/portal', action: 'click', selector: '#go' },
    { id: 'p3', role: 'probe', description: 'snapshot', origin, pathAndQuery: '/portal', action: 'dom_xss_sink_hook' },
  ]

  test('maps navigate/fill/click onto recipe steps and treats the sink snapshot as implicit', () => {
    const envelope = browserSinkEnvelopeFromSteps({ origin, vulnClass: 'dom_xss', steps: domSteps })
    assert.ok(envelope)
    assert.equal(envelope.recipeId, 'browser_sink')
    assert.equal(envelope.args.vulnClass, 'dom_xss')
    assert.deepEqual(envelope.args.steps?.map(step => step.action), ['navigate', 'fill', 'click'])
    assert.equal(envelope.args.steps?.[1]?.value, '{{canary_token}}')
    assert.equal(envelope.args.steps?.[0]?.role, 'control')
    assert.equal(envelope.args.steps?.[1]?.role, 'probe')
  })

  test('the wired mapping sends browser_chain xss to browser_sink', () => {
    assert.equal(wiredRecipeForSpecKind('browser_chain', 'xss'), 'browser_sink')
    assert.equal(wiredRecipeForSpecKind('browser_chain', 'xss_reflected'), 'browser_sink')
    // Protocol classes are not wired: they stay on the framework verifier.
    assert.equal(wiredRecipeForSpecKind('browser_chain', 'cors_client_side'), null)
  })

  test('protocol proofs are excluded rather than flattened', () => {
    const postMessage = [{ id: 'p', role: 'probe', description: 'pm', origin, pathAndQuery: '/', action: 'postmessage_probe' }]
    const fetchStep = [{ id: 'p', role: 'probe', description: 'cors', origin, pathAndQuery: '/', action: 'same_site_fetch', fetchTarget: { origin, pathAndQuery: '/api', method: 'GET', credentials: 'include' } }]
    const builtin = [{ id: 'p', role: 'probe', description: 'storage', origin, pathAndQuery: '/', action: 'navigate', builtinCheck: 'storage_keys' }]
    for (const steps of [postMessage, fetchStep, builtin]) {
      assert.equal(isProtocolBrowserSpec(steps), true)
      assert.equal(browserSinkEnvelopeFromSteps({ origin, vulnClass: 'dom_xss', steps }), null)
    }
    assert.equal(isProtocolBrowserSpec(domSteps), false)
  })

  test('confirms only when the probe session recorded the canary in an executable sink', async () => {
    const envelope = browserSinkEnvelopeFromSteps({ origin, vulnClass: 'dom_xss', steps: domSteps })!
    const sessions: Array<{ steps: number; hit: boolean }> = []
    const deps = depsFor(() => ({ status: 200 }), {
      browserSession: input => {
        const hit = input.steps.some(step => step.role === 'probe')
        sessions.push({ steps: input.steps.length, hit })
        return { traces: hit ? [{ id: 'trace-probe', origin, sinks: ['dom_xss:innerHTML'] }] : [], sinkHit: hit }
      },
    })
    const execution = await runCut3Recipe(cut3FloorRecipe('browser_sink', envelope.args), deps)
    assert.equal(execution.result.confirmed, true, execution.result.verification.reason)
    assert.equal(execution.result.verification.rule, 'browser')
    assert.deepEqual(execution.receipt.browserTraceIds, ['trace-probe'])
    assert.equal(sessions.length, 2, 'a control session runs before the probe session')
    assert.equal(sessions[0]?.hit, false)
  })

  test('fails closed when the probe session recorded no canary sink', async () => {
    const envelope = browserSinkEnvelopeFromSteps({ origin, vulnClass: 'dom_xss', steps: domSteps })!
    const execution = await runCut3Recipe(
      cut3FloorRecipe('browser_sink', envelope.args),
      depsFor(() => ({ status: 200 }), { browserSession: () => ({ traces: [], sinkHit: false }) }),
    )
    assert.equal(execution.result.confirmed, false)
    assert.ok(execution.failure?.missingRoles.includes('browser_sink'), JSON.stringify(execution.failure))
  })

  test('fails closed when the control session already hits the sink', async () => {
    const envelope = browserSinkEnvelopeFromSteps({ origin, vulnClass: 'dom_xss', steps: domSteps })!
    const execution = await runCut3Recipe(
      cut3FloorRecipe('browser_sink', envelope.args),
      depsFor(() => ({ status: 200 }), { browserSession: () => ({ traces: [{ id: 't', origin, sinks: ['dom_xss:innerHTML'] }], sinkHit: true }) }),
    )
    assert.equal(execution.result.confirmed, false)
    assert.ok(execution.failure?.missingRoles.includes('browser_control'), JSON.stringify(execution.failure))
  })
})

describe('cut3cd: browser session seam evidence channels', () => {
  const visit = (overrides: Record<string, unknown>) => ({
    origin,
    finalUrl: `${origin}/portal`,
    title: 'Portal',
    status: 200,
    domSnippet: '<div></div>',
    links: [],
    forms: [],
    xhrRequests: [],
    blockedOrigins: [],
    consoleMessages: [],
    postMessageListeners: { count: 0, hasOnMessage: false, handlers: [], observedEvents: 0, canaryHandledWithoutOriginCheck: false },
    cookieNames: [],
    localStorageKeys: [],
    sessionStorageKeys: [],
    canaryCheck: { token: null, triggered: false, detail: null },
    domSinkTraces: [],
    exchangeIds: [],
    exchanges: [],
    durationMs: 1,
    ...overrides,
  })

  function seam(visits: unknown[]) {
    const browser = { async runBrowserSession() { return visits } } as unknown as ScopedBrowser
    return browserSessionSeam({ browser, grant: {} as never, signal: AbortSignal.timeout(1000), origin })
  }

  test('cites an exact document-title canary assignment as execution evidence', async () => {
    const result = await seam([visit({ title: 'kovo-dom-abc123' })])({
      origin,
      steps: [{ role: 'probe', action: 'navigate', pathAndQuery: '/' }],
      canaryToken: 'kovo-dom-abc123',
      actor,
    })
    assert.equal(result?.sinkHit, true)
    assert.deepEqual(result?.traces[0]?.sinks, ['canary:title'])
  })

  test('a title that merely contains the canary text is not execution evidence', async () => {
    const result = await seam([visit({ title: 'Search results for kovo-dom-abc123' })])({
      origin,
      steps: [{ role: 'probe', action: 'navigate', pathAndQuery: '/' }],
      canaryToken: 'kovo-dom-abc123',
      actor,
    })
    assert.equal(result?.sinkHit, false)
    assert.deepEqual(result?.traces, [])
  })

  test('cites a DOM sink trace with the canary', async () => {
    const result = await seam([visit({ domSinkTraces: [{ sink: 'innerHTML', preview: 'x', containsCanary: true, timestamp: 1 }] })])({
      origin,
      steps: [{ role: 'probe', action: 'navigate', pathAndQuery: '/' }],
      canaryToken: 'kovo-dom-abc123',
      actor,
    })
    assert.equal(result?.sinkHit, true)
    assert.deepEqual(result?.traces[0]?.sinks, ['dom_xss:innerHTML'])
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
    // The receipt boolean rule pairs a TRUE predicate (control) with a FALSE one (probe): a
    // benign baseline vs true arm is structurally identical and could never confirm.
    assert.match(String(recipe!.args.controlPathAndQuery), /1%3D1|1=1/)
    assert.match(String(recipe!.args.probePathAndQuery), /1%3D2|1=2/)
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
    runId: 'run-v7-cut3cd-conserved',
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

// ---------------------------------------------------------------------------
// Cut 3d/3c: carrier coverage for the SQL recipe envelope (xben-25 regression)
// ---------------------------------------------------------------------------

function outcomeFor(location: 'form' | 'header' | 'path' | 'xml' | 'query', anomalies: Array<Record<string, unknown>>, pathAndQuery: string): HypothesisOutcome {
  return {
    hyp: {
      endpoint: { origin, path: pathAndQuery, method: 'POST', params: [{ name: 'q', location }] },
      method: 'POST',
      path: pathAndQuery,
      param: { name: 'q', location },
      location,
    },
    verdict: 'signal',
    anomalies,
    details: { booleanSignals: [{ passed: true, rounds: [{ statusBase: 200, statusTrue: 200, statusFalse: 200 }] }] },
    csrfRejected: false,
    contextReset: false,
    tierBlocked: false,
    requests: 4,
    ctx: { baseline: 'manuals' },
  } as unknown as HypothesisOutcome
}

const carrierEnv = { origin, owner: 'owner', caps: { sessionAndCsrf: false }, session: 's' } as unknown as ProbeEnv

describe('cut3cd: SQL recipe carrier coverage', () => {
  test('form carriers send url-encoded true/false arms, not JSON', () => {
    const specs = synthSqlBoolean(outcomeFor('form', [{ type: 'boolean_differential', style: 'and_branch', baselineValue: 'manuals' }], '/search/form'), carrierEnv)
    const args = (specs[0]!.spec as { recipe: { args: Record<string, { textBody?: string }> } }).recipe.args
    assert.match(String(args.controlRequest.textBody), /q=manuals%27\+AND\+1%3D1/)
    assert.match(String(args.probeRequest.textBody), /q=manuals%27\+AND\+1%3D2/)
  })

  test('header carriers vary the named header', () => {
    const specs = synthSqlBoolean(outcomeFor('header', [{ type: 'boolean_differential', style: 'and_branch', baselineValue: 'trk-100' }], '/api/track'), carrierEnv)
    const args = (specs[0]!.spec as { recipe: { args: Record<string, { headers?: Record<string, string> }> } }).recipe.args
    assert.equal(args.controlRequest.headers?.q, "trk-100' AND 1=1-- -")
    assert.equal(args.probeRequest.headers?.q, "trk-100' AND 1=2-- -")
  })

  test('xml carriers replace the parameter element', () => {
    const specs = synthSqlBoolean(outcomeFor('xml', [{ type: 'boolean_differential', style: 'and_branch', baselineValue: 'atlas' }], '/api/xml/lookup'), carrierEnv)
    const args = (specs[0]!.spec as { recipe: { args: Record<string, { textBody?: string }> } }).recipe.args
    assert.match(String(args.probeRequest.textBody), /<q>.*1=2/)
  })

  test('path carriers vary only the injected segment', () => {
    const specs = synthSqlBoolean(outcomeFor('path', [{ type: 'boolean_differential', style: 'and_branch', baselineValue: 'sku-100' }], '/api/items/sku-100'), carrierEnv)
    const args = (specs[0]!.spec as { recipe: { args: Record<string, { pathAndQuery?: string }> } }).recipe.args
    assert.match(String(args.probeRequest.pathAndQuery), /^\/api\/items\//)
    assert.notEqual(args.controlRequest.pathAndQuery, args.probeRequest.pathAndQuery)
  })

  test('timing carriers send a conditional delay and select the timing receipt rule', () => {
    const specs = synthSqlTime(outcomeFor('query', [{ type: 'sql_time_differential', style: 'single_quote', dialect: 'sqlite', delayMs: 1500, baselineValue: 'ref-100' }], '/api/orders/lookup'), carrierEnv)
    const args = (specs[0]!.spec as { recipe: { args: Record<string, unknown> } }).recipe.args
    assert.equal(args.receiptClass, 'blind_sqli')
    assert.match(String((args.probeRequest as { pathAndQuery?: string }).pathAndQuery), /RANDOMBLOB|SLEEP|pg_sleep|WAITFOR/)
  })
})

describe('cut3cd: dotted JSON parameter carriers', () => {
  test('a nested parameter is written as a nested object, not a literal dotted key', () => {
    const outcome = {
      hyp: {
        endpoint: { origin, path: '/api/v1/analytics/query', method: 'POST', params: [{ name: 'filter.name', location: 'json' }] },
        method: 'POST',
        path: '/api/v1/analytics/query',
        param: { name: 'filter.name', location: 'json' },
        location: 'json',
      },
      verdict: 'signal',
      anomalies: [{ type: 'sql_time_differential', style: 'single_quote', dialect: 'sqlite', delayMs: 1500, baselineValue: 'load' }],
      details: {},
      csrfRejected: false,
      contextReset: false,
      tierBlocked: false,
      requests: 4,
      ctx: { baseline: 'load' },
    } as unknown as HypothesisOutcome
    const specs = synthSqlTime(outcome, { origin, owner: 'owner', caps: { sessionAndCsrf: false }, session: 's' } as unknown as ProbeEnv)
    const args = (specs[0]!.spec as { recipe: { args: Record<string, unknown> } }).recipe.args
    const probe = args.probeRequest as { jsonBody?: { filter?: { name?: string } } }
    assert.ok(probe.jsonBody?.filter, 'the injected value must live under body.filter')
    assert.match(String(probe.jsonBody?.filter?.name), /RANDOMBLOB|SLEEP|pg_sleep|WAITFOR/)
    assert.equal((probe.jsonBody as Record<string, unknown>)['filter.name'], undefined, 'no literal dotted key')
  })
})
