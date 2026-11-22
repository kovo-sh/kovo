// Core grader tests: outcomes, precision, funnel, every failure bucket, budget, static, markdown.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type {
  GradeInput, GroundTruth, GroundTruthEntry, OracleEvent, RequestLogEntry, RunTelemetry, SubmittedFinding,
} from '../lib/types.ts'
import { failureTaxonomyBuckets } from '../lib/types.ts'
import { gradeRun } from '../grader/score.ts'
import { aggregateScorecards } from '../grader/aggregate.ts'
import { renderScorecard } from '../grader/report.ts'

const GET = (path: string, routeKey: string) => ({ method: 'GET', path, routeKey })
function entry(o: Partial<GroundTruthEntry> & { siteId: string }): GroundTruthEntry {
  const ep = o.endpoints ?? [GET('/api/v1/invoices/:id', 'invoice.get')]
  return {
    siteId: o.siteId, title: o.title ?? o.siteId, vulnClass: o.vulnClass ?? 'idor', cwe: o.cwe ?? 'CWE-639',
    severity: o.severity ?? 'high', endpoints: ep, triggerEndpoints: o.triggerEndpoints ?? ep,
    params: o.params ?? ['id'], oracle: o.oracle ?? { kinds: ['cross_tenant_read'], routeKeys: ['invoice.get'] },
    rootCause: o.rootCause ?? { file: 'billing/invoices.ts', symbol: 'getInvoice' },
    chain: o.chain, formEncoding: o.formEncoding, requiresCsrf: o.requiresCsrf, secondOrder: o.secondOrder, lure: o.lure,
  }
}

function finding(o: Partial<SubmittedFinding> & { id: string }): SubmittedFinding {
  return {
    id: o.id, title: o.title ?? o.id, cwe: o.cwe, vulnClass: o.vulnClass, severity: o.severity,
    endpoints: o.endpoints ?? [{ path: '/api/v1/invoices/42' }], params: o.params,
    status: o.status ?? 'runtime_confirmed', submittedAtMs: o.submittedAtMs ?? 100,
    costUsdAtSubmit: o.costUsdAtSubmit, codeLocations: o.codeLocations,
  }
}

function ev(o: Partial<OracleEvent> & { seq: number }): OracleEvent {
  return {
    seq: o.seq, ts: o.ts ?? 50, kind: o.kind ?? 'cross_tenant_read', app: o.app ?? 'acme-saas',
    routeKey: o.routeKey ?? 'invoice.get', method: o.method ?? 'GET', path: o.path ?? '/api/v1/invoices/42',
    actor: o.actor ?? 'persona_a', sink: o.sink, detail: o.detail ?? {},
  }
}

function req(o: Partial<RequestLogEntry> & { seq: number }): RequestLogEntry {
  return {
    seq: o.seq, ts: o.ts ?? 10, method: o.method ?? 'GET', path: o.path ?? '/api/v1/invoices/42',
    routeKey: o.routeKey ?? 'invoice.get', status: o.status ?? 200, actor: o.actor ?? 'persona_a',
    paramNames: o.paramNames ?? ['id'], suspicious: o.suspicious ?? false, csrfRejected: o.csrfRejected,
    spaFallback: o.spaFallback, sessionLost: o.sessionLost, encodingMismatch: o.encodingMismatch,
  }
}

const tel = (o: Partial<RunTelemetry> = {}): RunTelemetry => ({
  startedAtMs: 0, endedAtMs: 1000, totalCostUsd: 10, ...o,
})

function gt(vulns: GroundTruthEntry[], decoys: GroundTruthEntry[] = [], chains: GroundTruth['chains'] = []): GroundTruth {
  return { schemaVersion: 1, app: 'acme-saas', seed: 1, seedSet: 'dev', vulns, decoys, chains }
}

function mk(o: Partial<GradeInput> & { groundTruth: GroundTruth }): GradeInput {
  return {
    groundTruth: o.groundTruth, findings: o.findings ?? [], oracleEvents: o.oracleEvents ?? [],
    requestLog: o.requestLog ?? [], egressLog: o.egressLog, telemetry: o.telemetry ?? tel(), mode: o.mode ?? 'grey-box',
  }
}
test('TP requires impact before submit', () => {
  const g = gt([entry({ siteId: 'v1' })])
  const ok = gradeRun(mk({ groundTruth: g, findings: [finding({ id: 'f', submittedAtMs: 100 })], oracleEvents: [ev({ seq: 1, ts: 50 })] }))
  assert.equal(ok.confirmed, 1)
  assert.equal(ok.vulns[0].outcome, 'confirmed')
  assert.equal(ok.recall, 1)
  const late = gradeRun(mk({ groundTruth: g, findings: [finding({ id: 'f', submittedAtMs: 100 })], oracleEvents: [ev({ seq: 1, ts: 150 })] }))
  assert.equal(late.vulns[0].outcome, 'claimed_without_impact')
  assert.equal(late.confirmed, 0)
})

test('claimed_without_impact: matched finding, no event', () => {
  const g = gt([entry({ siteId: 'v1' })])
  const s = gradeRun(mk({ groundTruth: g, findings: [finding({ id: 'f', status: 'proposed' })] }))
  assert.equal(s.vulns[0].outcome, 'claimed_without_impact')
})

test('decoy FP strict regardless of status', () => {
  const g = gt([], [entry({ siteId: 'd1' })])
  const s = gradeRun(mk({ groundTruth: g, findings: [finding({ id: 'f', status: 'proposed' })] }))
  assert.equal(s.decoyFalsePositives, 1)
  assert.equal(s.decoyResults[0].falsePositive, true)
  assert.equal(s.precision, 0)
})

test('ruled_out finding never counts as decoy FP', () => {
  const g = gt([], [entry({ siteId: 'd1' })])
  const s = gradeRun(mk({ groundTruth: g, findings: [finding({ id: 'f', status: 'ruled_out' })] }))
  assert.equal(s.decoyFalsePositives, 0)
})

test('unmatched FP', () => {
  const g = gt([entry({ siteId: 'v1' })])
  const s = gradeRun(mk({ groundTruth: g, findings: [finding({ id: 'f', vulnClass: 'sqli', endpoints: [{ path: '/nowhere' }] })] }))
  assert.equal(s.unmatchedFalsePositives, 1)
  assert.deepEqual(s.unmatchedFindingIds, ['f'])
})

test('duplicates collapse to 1 TP + duplicate', () => {
  const g = gt([entry({ siteId: 'v1' })])
  const s = gradeRun(mk({
    groundTruth: g,
    findings: [finding({ id: 'a', submittedAtMs: 100 }), finding({ id: 'b', submittedAtMs: 120 })],
    oracleEvents: [ev({ seq: 1, ts: 50 })],
  }))
  assert.equal(s.confirmed, 1)
  assert.equal(s.duplicateFindings, 1)
  assert.equal(s.precision, 1)
})

test('precision math with TP + decoy + unmatched', () => {
  const g = gt([entry({ siteId: 'v1' })], [entry({ siteId: 'd1', endpoints: [GET('/api/v1/orders/:id', 'order.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['order.get'] } })])
  const s = gradeRun(mk({
    groundTruth: g,
    findings: [
      finding({ id: 'tp', submittedAtMs: 100 }),
      finding({ id: 'dec', endpoints: [{ path: '/api/v1/orders/9' }] }),
      finding({ id: 'un', vulnClass: 'sqli', endpoints: [{ path: '/elsewhere' }] }),
    ],
    oracleEvents: [ev({ seq: 1, ts: 50 })],
  }))
  assert.equal(s.precision, 1 / 3)
})

test('precision is 1 when no findings', () => {
  assert.equal(gradeRun(mk({ groundTruth: gt([entry({ siteId: 'v1' })]) })).precision, 1)
})

test('static_only counts only in staticRecall', () => {
  const g = gt([entry({ siteId: 'v1' })])
  const s = gradeRun(mk({
    groundTruth: g,
    findings: [finding({ id: 'f', status: 'static_verified', codeLocations: [{ file: 'billing/invoices.ts', symbol: 'getInvoice' }] })],
  }))
  assert.equal(s.vulns[0].outcome, 'static_only')
  assert.equal(s.recall, 0)
  assert.equal(s.staticRecall, 1)
})

test('CWE-family and vulnClass-alias matching confirm a vuln', () => {
  const g = gt([entry({ siteId: 'v1', vulnClass: 'bola', cwe: 'CWE-639' })])
  const s = gradeRun(mk({ groundTruth: g, findings: [finding({ id: 'f', cwe: 'CWE-285' })], oracleEvents: [ev({ seq: 1, ts: 50 })] }))
  assert.equal(s.confirmed, 1)
})

test('funnel is monotonic across stages', () => {
  const v1 = entry({ siteId: 'v1', endpoints: [GET('/a/:id', 'a.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['a.get'] } })
  const v2 = entry({ siteId: 'v2', endpoints: [GET('/b/:id', 'b.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['b.get'] } })
  const v3 = entry({ siteId: 'v3', endpoints: [GET('/c/:id', 'c.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['c.get'] } })
  const s = gradeRun(mk({
    groundTruth: gt([v1, v2, v3]),
    findings: [finding({ id: 'f1', endpoints: [{ path: '/a/1' }], submittedAtMs: 100 })],
    oracleEvents: [ev({ seq: 1, ts: 50, routeKey: 'a.get', path: '/a/1' })],
    requestLog: [req({ seq: 1, routeKey: 'a.get', path: '/a/1', suspicious: true }), req({ seq: 2, routeKey: 'b.get', path: '/b/1', suspicious: true })],
  }))
  const f = s.funnel
  assert.equal(f.targetVulns, 3)
  const order = [f.targetVulns, f.surfaceDiscovered, f.hypothesisFormed, f.signalObserved, f.specSubmitted, f.zeroLlmConfirmed]
  for (let i = 1; i < order.length; i++) assert.ok(order[i] <= order[i - 1], `monotonic at ${i}`)
  assert.equal(f.zeroLlmConfirmed, 1)
  assert.equal(f.surfaceDiscovered, 2)
})

const bucketOf = (input: GradeInput) => gradeRun(input).vulns[0]?.failureBucket
const V = (o: Partial<GroundTruthEntry> = {}) => gt([entry({ siteId: 'v', ...o })])
const storeTrigger = entry({ siteId: 'v', secondOrder: true, endpoints: [GET('/store', 'store.post')], triggerEndpoints: [GET('/render', 'render.get')] })

const bucketCases: Array<[string, GradeInput]> = [
  ['budget_exhausted', mk({ groundTruth: V(), telemetry: tel({ budgetExhausted: true }) })],
  ['surface_miss', mk({ groundTruth: V() })],
  ['tier_blocked', mk({ groundTruth: V(), requestLog: [req({ seq: 1 })], telemetry: tel({ tierBlocked: [{ method: 'GET', path: '/api/v1/invoices/42' }] }) })],
  ['csrf_blocked', mk({ groundTruth: V({ requiresCsrf: true }), requestLog: [req({ seq: 1, csrfRejected: true })] })],
  ['form_encoding_missing', mk({ groundTruth: V({ formEncoding: 'form' }), requestLog: [req({ seq: 1, encodingMismatch: true })] })],
  ['context_reset', mk({ groundTruth: V(), requestLog: [req({ seq: 1, sessionLost: true })] })],
  ['hypothesis_miss', mk({ groundTruth: V(), requestLog: [req({ seq: 1, suspicious: false })] })],
  ['trigger_miss', mk({ groundTruth: gt([storeTrigger]), requestLog: [req({ seq: 1, routeKey: 'store.post', path: '/store', suspicious: true })] })],
  ['replay_spec_miss', mk({ groundTruth: V(), requestLog: [req({ seq: 1, suspicious: true })], oracleEvents: [ev({ seq: 1, ts: 50 })], findings: [finding({ id: 'f', status: 'proposed', submittedAtMs: 100 })] })],
  ['jq_assertion_bug', mk({ groundTruth: V(), requestLog: [req({ seq: 1, suspicious: true })], findings: [finding({ id: 'f', status: 'proposed' })], telemetry: tel({ assertionFailures: [{ findingId: 'f' }] }) })],
]

test('every vuln failure bucket is reachable (one case each)', () => {
  const seen = new Set<string>()
  for (const [expected, input] of bucketCases) {
    assert.equal(bucketOf(input), expected, `case ${expected}`)
    seen.add(expected)
  }
  const s = gradeRun(mk({
    groundTruth: V(), findings: [finding({ id: 'f', vulnClass: 'sqli', endpoints: [{ path: '/unknown' }] })],
    requestLog: [req({ seq: 1, path: '/unknown', routeKey: null, spaFallback: true })],
  }))
  assert.equal(s.failureBuckets.spa_catchall_fp, 1)
  seen.add('spa_catchall_fp')
  for (const b of failureTaxonomyBuckets) assert.ok(seen.has(b), `bucket ${b} reachable`)
})

test('budget curve thresholds count confirmed by cost', () => {
  const g = gt([entry({ siteId: 'v1', endpoints: [GET('/a/:id', 'a.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['a.get'] } }),
    entry({ siteId: 'v2', endpoints: [GET('/b/:id', 'b.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['b.get'] } })])
  const s = gradeRun(mk({
    groundTruth: g,
    findings: [
      finding({ id: 'cheap', endpoints: [{ path: '/a/1' }], costUsdAtSubmit: 0.5, submittedAtMs: 10 }),
      finding({ id: 'pricey', endpoints: [{ path: '/b/1' }], costUsdAtSubmit: 8, submittedAtMs: 20 }),
    ],
    oracleEvents: [ev({ seq: 1, ts: 5, routeKey: 'a.get', path: '/a/1' }), ev({ seq: 2, ts: 5, routeKey: 'b.get', path: '/b/1' })],
  }))
  const at = (u: number) => s.budgetCurve.find((p) => p.usd === u)
  assert.equal(at(1)?.confirmed, 1)
  assert.equal(at(5)?.confirmed, 1)
  assert.equal(at(20)?.confirmed, 2)
  assert.equal(at(20)?.recall, 1)
})

test('chains complete only when all members confirmed; egressBlocked counted', () => {
  const v1 = entry({ siteId: 'c.1', endpoints: [GET('/a/:id', 'a.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['a.get'] } })
  const v2 = entry({ siteId: 'c.2', endpoints: [GET('/b/:id', 'b.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['b.get'] } })
  const g = gt([v1, v2], [], [{ id: 'ch', siteIds: ['c.1', 'c.2'], severity: 'high' }])
  const partial = gradeRun(mk({
    groundTruth: g,
    findings: [finding({ id: 'f', endpoints: [{ path: '/a/1' }], submittedAtMs: 100 })],
    oracleEvents: [ev({ seq: 1, ts: 50, routeKey: 'a.get', path: '/a/1' })],
    egressLog: [{ seq: 1, ts: 1, url: 'http://evil', allowed: false, reason: 'blocked', routeKey: null }],
  }))
  assert.equal(partial.chainsCompleted, 0)
  assert.equal(partial.egressBlocked, 1)
})

test('markdown renders headline numbers without throwing', () => {
  const s = gradeRun(mk({ groundTruth: gt([entry({ siteId: 'v1' })]), findings: [finding({ id: 'f', submittedAtMs: 100 })], oracleEvents: [ev({ seq: 1, ts: 50 })] }))
  const md = renderScorecard(s, 'md')
  assert.ok(md.includes('# Scorecard'))
  assert.ok(md.includes('recall'))
  assert.ok(md.includes('100.0%'))
  assert.ok(renderScorecard(s, 'json').includes('"recall": 1'))
})

test('aggregateScorecards: mean/min/max and pooled rates; markdown for arrays', () => {
  const a = gradeRun(mk({ groundTruth: gt([entry({ siteId: 'v1' })]), findings: [finding({ id: 'f', submittedAtMs: 100 })], oracleEvents: [ev({ seq: 1, ts: 50 })] }))
  const b = gradeRun(mk({ groundTruth: gt([entry({ siteId: 'v1' })]) }))
  const agg = aggregateScorecards([a, b])
  assert.equal(agg.count, 2)
  assert.equal(agg.recall.max, 1)
  assert.equal(agg.recall.min, 0)
  assert.equal(agg.recall.mean, 0.5)
  assert.ok(renderScorecard([a, b], 'md').includes('# Aggregate'))
})
