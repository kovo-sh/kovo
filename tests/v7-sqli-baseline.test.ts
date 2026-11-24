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

const ORIGIN = 'http://sqli-baseline.invalid'
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
