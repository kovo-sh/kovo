/**
 * SQLi boolean differential — baseline grounding.
 *
 * HELDOUT-LIFT §6.7: a boolean pair whose leading operand does not exist in the target's catalog
 * (a dev fixture word, a seed literal) returns zero rows for the true arm, so the differential can
 * never separate even when the sink is injectable. The probe must harvest an operand from a benign
 * response and fall back to a tautology pair — never to an app/seed literal. These tests use a fake
 * broker so the harness never touches the network.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

import type { BrokerExchangeResult, Grant, RequestBroker } from '../src/server/broker.ts'
import type { ProbeDifferentialRequest } from '../src/server/probes/context.ts'
import { probeDifferential } from '../src/server/surface-engine.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'
import type { EngineHypothesis } from '../src/server/deterministic-specs.ts'
import {
  planFloorRecipe,
  recipeSpecRecord,
  runPlannedRecipe,
} from '../src/server/floor-recipe-engine.ts'

const ORIGIN = 'https://sqli-baseline.invalid'
const PATH = '/api/search'

const grant: Grant = {
  origin: ORIGIN,
  tier: 3,
  allowLocalLab: true,
  maxRpsPerOrigin: 200,
  canRead: o => o === ORIGIN,
  isIdempotentPostAllowed: () => true,
  isStateChangeApproved: () => true,
  audit: () => undefined,
}

function exchange(pathAndQuery: string, body: string): BrokerExchangeResult {
  return {
    origin: ORIGIN,
    finalOrigin: ORIGIN,
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery,
    personaHandle: null,
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: { 'content-type': 'application/json' },
    setCookies: [],
    bodyPreview: body.slice(0, 2000),
    body,
    bodySha256: createHash('sha256').update(body).digest('hex'),
    bodyBytes: Buffer.byteLength(body),
    bodyTruncated: false,
    durationMs: 1,
    observation: {} as BrokerExchangeResult['observation'],
  }
}

/** A fake broker whose transport is a pure function of the requested path+query. */
function fakeBroker(handler: (query: string) => { query: string; results: Array<Record<string, unknown>> }, seen: string[] = []): RequestBroker {
  return {
    async executeHttp(request: { pathAndQuery: string }) {
      const url = new URL(request.pathAndQuery, ORIGIN)
      const q = url.searchParams.get('query') ?? ''
      seen.push(q)
      return exchange(request.pathAndQuery, JSON.stringify(handler(q)))
    },
  } as unknown as RequestBroker
}

const probeReq = (baselineValue: string): ProbeDifferentialRequest => ({
  probeClass: 'sqli_boolean',
  origin: ORIGIN,
  pathAndQuery: `${PATH}?query=placeholder`,
  param: 'query',
  paramLocation: 'query',
  baselineValue,
})

async function probe(broker: RequestBroker, baselineValue = 'Item'): Promise<DifferentialResult> {
  return probeDifferential(probeReq(baselineValue), broker, grant, undefined, AbortSignal.timeout(10_000))
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const like = (pattern: string, value: string) =>
  new RegExp(`^${pattern.split('%').map(escape).join('.*')}$`, 'i').test(value)

/**
 * Emulate `title LIKE '%${q}%'` with the `-- -` comment eating the trailing `%'`, and evaluate the
 * appended AND/OR equality predicate. `hardened` binds the term as a literal LIKE value instead.
 */
function searchable(options: {
  catalog: string[]
  hardened?: boolean
  /** Predicate oracle: return this row whenever the injected predicate is true (empty catalog). */
  predicateRows?: string[]
}) {
  const { catalog, hardened = false, predicateRows } = options
  return (q: string) => {
    if (hardened) {
      return { query: q, results: catalog.filter(title => title.includes(q)).map(title => ({ title })) }
    }
    if (q === '') return { query: q, results: catalog.map(title => ({ title })) }
    const comment = q.indexOf('-- -')
    const before = comment >= 0 ? q.slice(0, comment) : q
    const quote = before.indexOf("'")
    let pattern: string
    let predicate: string
    if (quote >= 0) {
      pattern = `%${before.slice(0, quote)}`
      if (comment < 0) pattern += '%'
      predicate = before.slice(quote + 1)
    } else {
      pattern = `%${before}${comment < 0 ? '%' : ''}`
      predicate = ''
    }
    const equality = /(?:AND|OR)\s+(\d+)\s*=\s*(\d+)/i.exec(predicate)
    const tautologyTrue = /\bOR\b\s*'1'\s*=\s*'1/i.test(predicate)
    const tautologyFalse = /\bAND\b\s*'1'\s*=\s*'2/i.test(predicate)
    const holds = tautologyTrue ? true : tautologyFalse ? false : equality ? equality[1] === equality[2] : true
    if (predicateRows) {
      const injected = predicate.trim().length > 0
      return { query: q, results: holds && injected ? predicateRows.map(title => ({ title })) : [] }
    }
    return { query: q, results: holds ? catalog.filter(title => like(pattern, title)).map(title => ({ title })) : [] }
  }
}

test('sql-baseline: a catalog without the dev literal still confirms from a harvested operand', async () => {
  const seen: string[] = []
  const catalog = ['Zephyr 9', 'Lumen 4']
  const res = await probe(fakeBroker(searchable({ catalog }), seen), 'Item')
  assert.equal(res.verdict, 'signal', res.summary)
  const anomaly = res.anomalies.find(a => a.type === 'boolean_differential')
  assert.ok(anomaly, 'expected a boolean differential anomaly')
  const grounded = String(anomaly.baselineValue)
  assert.ok(catalog.includes(grounded), `grounded operand ${grounded} must come from the catalog`)
  assert.equal(anomaly.provenStyle, 'single_quote')
  assert.equal(anomaly.style, 'single_quote')
  assert.equal(res.details.baselineSource, 'harvested')
  assert.equal(res.details.groundedBaselineValue, grounded)
  // The true arm leads with the harvested operand and appends the SQL predicate.
  assert.ok(seen.some(q => q.startsWith(`${grounded}' AND `) || q.startsWith(`${grounded}%' AND `)),
    'a true arm must lead with the harvested operand')
  const rounds = (res.details.booleanSignals as Array<{ rounds: Array<Record<string, unknown>> }>)[0]!.rounds
  for (const round of rounds) {
    assert.ok(Number(round.rowsTrue) > 0, 'the true arm keeps rows when the baseline had rows')
    assert.equal(round.rowsFalse, 0)
  }
})

test('sql-baseline: a rowless catalog falls back to the tautology pair and still confirms', async () => {
  const res = await probe(fakeBroker(searchable({ catalog: [], predicateRows: ['probe row'] })), 'Item')
  assert.equal(res.verdict, 'signal', res.summary)
  const anomaly = res.anomalies.find(a => a.type === 'boolean_differential')
  assert.ok(anomaly)
  assert.equal(anomaly.provenStyle, 'tautology')
  assert.equal(anomaly.style, 'or_branch')
  assert.equal(res.details.baselineSource, 'tautology')
  assert.equal(res.details.groundedBaselineValue, null)
})

test('sql-baseline: a hardened parameterized lookup never confirms', async () => {
  const res = await probe(fakeBroker(searchable({ catalog: ['Zephyr 9', 'Lumen 4'], hardened: true })), 'Item')
  assert.notEqual(res.verdict, 'signal', res.summary)
  assert.equal(res.anomalies.filter(a => a.type === 'boolean_differential').length, 0)
})

test('sql-baseline: a target whose arms stay empty is inconclusive, never confirmed', async () => {
  const res = await probe(fakeBroker(() => ({ query: '', results: [] })), 'Item')
  assert.notEqual(res.verdict, 'signal', res.summary)
  assert.equal(res.verdict, 'inconclusive', res.summary)
  assert.equal(res.anomalies.length, 0)
})

// ---------------------------------------------------------------------------------------------
// Cut 3a: the live confirmation paths must replay the grounded pair.
// ---------------------------------------------------------------------------------------------

function searchHypothesis(): EngineHypothesis {
  return {
    key: 'sqli|search',
    endpoint: {
      id: 'GET:/api/search',
      origin: ORIGIN,
      method: 'GET',
      pathTemplate: PATH,
      params: [{ name: 'query', location: 'query' }],
    },
    probeClass: 'sqli_boolean',
    intent: 'sqli',
    method: 'GET',
    pathAndQuery: PATH,
    param: { name: 'query', location: 'query' },
    location: 'query',
    baselineValue: 'Item',
    risk: 80,
  }
}

/** The anomaly shape the grounded probe emits, without spending probe requests. */
function groundedProbe(baselineValue: string, provenStyle = 'like_breakout'): DifferentialResult {
  return {
    probeClass: 'sqli_boolean',
    origin: ORIGIN,
    pathAndQuery: PATH,
    verdict: 'signal',
    summary: 'grounded',
    requestsSent: 0,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 1,
    anomalies: [{
      type: 'boolean_differential',
      style: provenStyle,
      provenStyle,
      baselineValue,
      quoteStyle: 'single',
      valueTemplate: "{{baseline}}%' AND {{sql_expr}}-- -",
    }],
    details: { groundedBaselineValue: baselineValue },
  }
}

/** Echo-only target: every arm returns the same rows and only reflects the query back. */
function echoBroker(seen: string[] = []): RequestBroker {
  return {
    async executeHttp(request: { pathAndQuery: string }) {
      const url = new URL(request.pathAndQuery, ORIGIN)
      const q = url.searchParams.get('query') ?? ''
      seen.push(q)
      return exchange(request.pathAndQuery, JSON.stringify({
        query: q,
        results: [{ title: 'Zephyr 9' }, { title: 'Lumen 4' }],
      }))
    },
  } as unknown as RequestBroker
}

test('sql-baseline: the recipe plan replays the grounded operand and proven shape', () => {
  const plan = planFloorRecipe({
    hypothesis: searchHypothesis(),
    probe: groundedProbe('Zephyr 9'),
    specKind: 'sql_boolean_diff',
    vulnClass: 'sqli',
    personas: [],
  })
  assert.ok(plan, 'sql_boolean_diff must be wired')
  assert.equal(plan.skipReason, undefined)
  const args = plan.args as { baselineValue?: string; controlPathAndQuery?: string; probePathAndQuery?: string; valueTemplate?: string }
  assert.equal(args.baselineValue, 'Zephyr 9')
  const controlValue = new URL(args.controlPathAndQuery!, ORIGIN).searchParams.get('query') ?? ''
  const probeValue = new URL(args.probePathAndQuery!, ORIGIN).searchParams.get('query') ?? ''
  assert.ok(controlValue.startsWith('Zephyr 9%'), `control arm must lead with the grounded term: ${controlValue}`)
  assert.ok(probeValue.startsWith('Zephyr 9%'), `probe arm must lead with the grounded term: ${probeValue}`)
  assert.ok(probeValue.includes("'"), 'the probe arm must keep the quote breakout')
  assert.equal(args.valueTemplate, "{{baseline}}%' AND {{sql_expr}}-- -")
  assert.ok(!/Item/.test(controlValue), 'a dev catalog term must never reach the recipe')
})

test('sql-baseline: a wired recipe confirms on a catalog lacking the dev literal', async () => {
  const plan = planFloorRecipe({
    hypothesis: searchHypothesis(),
    probe: groundedProbe('Zephyr 9'),
    specKind: 'sql_boolean_diff',
    vulnClass: 'sqli',
    personas: [],
  })!
  const seen: string[] = []
  const execution = await runPlannedRecipe({
    plan,
    hypothesis: searchHypothesis(),
    broker: fakeBroker(searchable({ catalog: ['Zephyr 9', 'Lumen 4'] }), seen),
    grant,
    signal: AbortSignal.timeout(10_000),
    recordExchange: (() => { let n = 0; return () => `rx-${++n}` })(),
  })
  assert.equal(execution.result.confirmed, true, execution.failure?.message ?? 'unexpected rejection')
  assert.ok(seen.every(q => q.startsWith('Zephyr 9%')), `every arm must be grounded (${seen.join(', ')})`)
  const record = recipeSpecRecord(plan, execution).spec as { baselineValue?: string; valueTemplate?: string }
  assert.equal(record.baselineValue, 'Zephyr 9')
  assert.equal(record.valueTemplate, "{{baseline}}%' AND {{sql_expr}}-- -")
})

test('sql-baseline: the same wired recipe rejects a hardened catalog', async () => {
  const plan = planFloorRecipe({
    hypothesis: searchHypothesis(),
    probe: groundedProbe('Zephyr 9'),
    specKind: 'sql_boolean_diff',
    vulnClass: 'sqli',
    personas: [],
  })!
  const execution = await runPlannedRecipe({
    plan,
    hypothesis: searchHypothesis(),
    broker: fakeBroker(searchable({ catalog: ['Zephyr 9', 'Lumen 4'], hardened: true })),
    grant,
    signal: AbortSignal.timeout(10_000),
    recordExchange: (() => { let n = 0; return () => `hx-${++n}` })(),
  })
  assert.equal(execution.result.confirmed, false)
  assert.equal(execution.failure?.code, 'receipt_rejected')
})

test('sql-baseline: an echo-only target is rejected by the receipt rule', async () => {
  const plan = planFloorRecipe({
    hypothesis: searchHypothesis(),
    probe: groundedProbe('Zephyr 9'),
    specKind: 'sql_boolean_diff',
    vulnClass: 'sqli',
    personas: [],
  })!
  const seen: string[] = []
  const execution = await runPlannedRecipe({
    plan,
    hypothesis: searchHypothesis(),
    broker: echoBroker(seen),
    grant,
    signal: AbortSignal.timeout(10_000),
    recordExchange: (() => { let n = 0; return () => `ex-${++n}` })(),
  })
  assert.equal(execution.result.confirmed, false)
  assert.equal(execution.failure?.code, 'receipt_rejected')
})

test('sql-baseline: a tautology-proven pair replays through the probe single-template', () => {
  const probeResult = groundedProbe('', 'tautology')
  // The probe normalizes the legacy style to or_branch and exposes `provenStyle: 'tautology'`.
  ;(probeResult.anomalies[0] as Record<string, unknown>).style = 'or_branch'
  const plan = planFloorRecipe({
    hypothesis: searchHypothesis(),
    probe: probeResult,
    specKind: 'sql_boolean_diff',
    vulnClass: 'sqli',
    personas: [],
  })
  assert.ok(plan)
  const args = plan.args as { baselineValue?: string; controlPathAndQuery?: string; probePathAndQuery?: string; valueTemplate?: string }
  assert.equal(args.baselineValue, '')
  assert.equal(args.valueTemplate, "{{baseline}}%' AND {{sql_expr}}-- -")
  const controlValue = new URL(args.controlPathAndQuery!, ORIGIN).searchParams.get('query') ?? ''
  const probeValue = new URL(args.probePathAndQuery!, ORIGIN).searchParams.get('query') ?? ''
  assert.equal(controlValue, "%' AND 7919=7919-- -")
  assert.equal(probeValue, "%' AND 7919=7920-- -")
})
