// Grader soundness: confirmation needs oracle evidence for the *same* (kind, routeKey) pair, class
// mismatches and sibling routes never bind to a site, and decoy/unmatched/TN accounting cannot
// silently drift between buckets.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type {
  GradeInput, GroundTruth, GroundTruthEntry, OracleEvent, RunTelemetry, SubmittedFinding,
} from '../lib/types.ts'
import { gradeRun } from '../grader/score.ts'

const GET = (path: string, routeKey: string) => ({ method: 'GET', path, routeKey })

function entry(o: Partial<GroundTruthEntry> & { siteId: string }): GroundTruthEntry {
  const ep = o.endpoints ?? [GET('/api/v1/invoices/:id', 'invoice.get')]
  return {
    siteId: o.siteId, title: o.title ?? o.siteId, vulnClass: o.vulnClass ?? 'bola', cwe: o.cwe ?? 'CWE-639',
    severity: o.severity ?? 'high', endpoints: ep, triggerEndpoints: o.triggerEndpoints ?? ep,
    params: o.params ?? ['id'], oracle: o.oracle ?? { kinds: ['cross_tenant_read'], routeKeys: ['invoice.get'] },
    rootCause: o.rootCause ?? { file: 'billing/invoices.ts', symbol: 'getInvoice' },
    chain: o.chain, formEncoding: o.formEncoding, requiresCsrf: o.requiresCsrf, secondOrder: o.secondOrder,
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

function event(o: Partial<OracleEvent> & { seq: number }): OracleEvent {
  return {
    seq: o.seq, ts: o.ts ?? 50, kind: o.kind ?? 'cross_tenant_read', app: o.app ?? 'acme-saas',
    routeKey: o.routeKey ?? 'invoice.get', method: 'GET', path: o.path ?? '/api/v1/invoices/42',
    actor: o.actor ?? 'persona_a', sink: o.sink, detail: o.detail ?? {},
  }
}

const tel = (o: Partial<RunTelemetry> = {}): RunTelemetry => ({ startedAtMs: 0, endedAtMs: 1000, totalCostUsd: 10, ...o })

function gt(vulns: GroundTruthEntry[], decoys: GroundTruthEntry[] = [], chains: GroundTruth['chains'] = []): GroundTruth {
  return { schemaVersion: 1, app: 'acme-saas', seed: 1, seedSet: 'dev', vulns, decoys, chains }
}

function mk(o: Partial<GradeInput> & { groundTruth: GroundTruth }): GradeInput {
  return {
    groundTruth: o.groundTruth, findings: o.findings ?? [], oracleEvents: o.oracleEvents ?? [],
    requestLog: o.requestLog ?? [], egressLog: o.egressLog, telemetry: o.telemetry ?? tel(), mode: o.mode ?? 'grey-box',
  }
}

const XSS = (siteId: string): GroundTruthEntry => entry({
  siteId, vulnClass: 'xss_stored', cwe: 'CWE-79', endpoints: [GET('/api/v1/cards/:id', 'card.update')],
  triggerEndpoints: [GET('/api/v1/cards/:id/view', 'card.view')],
  oracle: { kinds: ['stored_xss_rendered'], routeKeys: ['card.view'] },
})

test('class mismatch (authz claim on an XSS site) never matches a vuln or a decoy', () => {
  const authzClaim = { vulnClass: 'idor', cwe: 'CWE-639' }
  const vuln = gradeRun(mk({
    groundTruth: gt([XSS('xss-vuln')]),
    findings: [finding({ id: 'f', ...authzClaim, endpoints: [{ path: '/api/v1/cards/9/view' }] })],
    oracleEvents: [event({ seq: 1, kind: 'stored_xss_rendered', routeKey: 'card.view' })],
  }))
  assert.equal(vuln.confirmed, 0)
  assert.equal(vuln.unmatchedFalsePositives, 1)
  assert.equal(vuln.decoyFalsePositives, 0)

  const decoy = gradeRun(mk({
    groundTruth: gt([], [XSS('xss-decoy')]),
    findings: [finding({ id: 'f', ...authzClaim, endpoints: [{ path: '/api/v1/cards/9/view' }] })],
  }))
  assert.equal(decoy.decoyFalsePositives, 0, 'class-mismatched claim must not silently become a decoy FP')
  assert.equal(decoy.unmatchedFalsePositives, 1)
})

test('sibling action/inbox routes do not match their parent resource route', () => {
  const parent = entry({ siteId: 'v', endpoints: [GET('/api/v1/invoices/:id', 'invoice.get')] })
  const g = gt([parent], [entry({ siteId: 'd', endpoints: [GET('/api/v1/inbox/:id', 'inbox.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['inbox.get'] } })])
  const s = gradeRun(mk({
    groundTruth: g,
    findings: [
      finding({ id: 'sibling-read', endpoints: [{ path: '/api/v1/invoices/42/read' }] }),
      finding({ id: 'sibling-decoy', endpoints: [{ path: '/api/v1/inbox/42/read' }] }),
      finding({ id: 'wrong-method', endpoints: [{ method: 'POST', path: '/api/v1/invoices/42' }] }),
    ],
  }))
  assert.equal(s.confirmed, 0)
  assert.equal(s.decoyFalsePositives, 0)
  assert.equal(s.unmatchedFalsePositives, 3)

  const exact = gradeRun(mk({
    groundTruth: gt([parent]), findings: [finding({ id: 'f' })], oracleEvents: [event({ seq: 1 })],
  }))
  assert.equal(exact.confirmed, 1)
})

test('confirmation needs a matching kind AND routeKey before submit', () => {
  const g = gt([entry({ siteId: 'v' })])
  const base = { id: 'f', submittedAtMs: 100 }
  const cases: Array<[string, OracleEvent | undefined, boolean]> = [
    ['no evidence', undefined, false],
    ['wrong kind, same route', event({ seq: 1, kind: 'privilege_escalation', routeKey: 'invoice.get' }), false],
    ['right kind, sibling route', event({ seq: 1, routeKey: 'invoice.list' }), false],
    ['right kind, null route', { ...event({ seq: 1 }), routeKey: null }, false],
    ['right kind+route but after submit', event({ seq: 1, ts: 150 }), false],
    ['right kind+route before submit', event({ seq: 1, ts: 50 }), true],
  ]
  for (const [label, ev, confirmed] of cases) {
    const s = gradeRun(mk({ groundTruth: g, findings: [finding(base)], oracleEvents: ev ? [ev] : [] }))
    assert.equal(s.confirmed, confirmed ? 1 : 0, label)
    assert.equal(s.vulns[0]!.outcome, confirmed ? 'confirmed' : 'claimed_without_impact', label)
  }
})

test('decoy evidence is never credited to a vuln, and vuln evidence never clears a decoy', () => {
  const vuln = entry({ siteId: 'v', endpoints: [GET('/api/v1/invoices/:id', 'invoice.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['invoice.get'] } })
  const decoy = entry({
    siteId: 'd', endpoints: [GET('/api/v1/orders/:id', 'order.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['order.get'] },
  })
  const g = gt([vuln], [decoy])
  const onlyDecoyEvent = gradeRun(mk({
    groundTruth: g, findings: [finding({ id: 'f' })], oracleEvents: [event({ seq: 1, routeKey: 'order.get', path: '/api/v1/orders/9' })],
  }))
  assert.equal(onlyDecoyEvent.confirmed, 0)
  assert.equal(onlyDecoyEvent.vulns[0]!.outcome, 'claimed_without_impact')

  const decoyClaim = gradeRun(mk({
    groundTruth: g,
    findings: [finding({ id: 'd1', endpoints: [{ path: '/api/v1/orders/9' }] })],
    oracleEvents: [event({ seq: 1, routeKey: 'invoice.get' })],
  }))
  assert.equal(decoyClaim.decoyFalsePositives, 1)
  assert.equal(decoyClaim.decoyResults.find((r) => r.siteId === 'd')?.falsePositive, true)
  assert.equal(decoyClaim.confirmed, 0)
})

test('a multi-endpoint finding cannot hide decoy claims behind a vuln match', () => {
  const v = entry({ siteId: 'v', endpoints: [GET('/api/v1/invoices/:id', 'invoice.get')] })
  const d1 = entry({ siteId: 'd1', endpoints: [GET('/api/v1/orders/:id', 'order.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['order.get'] } })
  const d2 = entry({ siteId: 'd2', endpoints: [GET('/api/v1/shipments/:id', 'shipment.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['shipment.get'] } })
  const s = gradeRun(mk({
    groundTruth: gt([v], [d1, d2]),
    findings: [finding({
      id: 'bundle',
      endpoints: [{ path: '/api/v1/invoices/1' }, { path: '/api/v1/orders/1' }, { path: '/api/v1/shipments/1' }],
    })],
    oracleEvents: [event({ seq: 1, routeKey: 'invoice.get', path: '/api/v1/invoices/1' })],
  }))
  assert.equal(s.confirmed, 1)
  assert.equal(s.decoyFalsePositives, 2, 'every decoy site named by the finding is a false claim')
  assert.equal(s.unmatchedFalsePositives, 0)
  assert.equal(s.precision, 1 / 3) // 1 TP / (1 TP + 2 decoy sites)
})

test('finding partition: every active finding lands in exactly one bucket', () => {
  const v = entry({ siteId: 'v', endpoints: [GET('/api/v1/invoices/:id', 'invoice.get')] })
  const d = XSS('d')
  const g = gt([v], [d])
  const s = gradeRun(mk({
    groundTruth: g,
    findings: [
      finding({ id: 'tp', submittedAtMs: 100 }),
      finding({ id: 'tp-dup', submittedAtMs: 110 }),
      finding({ id: 'decoy', vulnClass: 'xss_stored', cwe: 'CWE-79', endpoints: [{ path: '/api/v1/cards/9/view' }] }),
      finding({ id: 'decoy-wrong-class', vulnClass: 'idor', cwe: 'CWE-639', endpoints: [{ path: '/api/v1/cards/9/view' }] }),
      finding({ id: 'unplanted', vulnClass: 'info_disclosure', endpoints: [{ path: '/api/health' }] }),
      finding({ id: 'ruled-out', status: 'ruled_out', vulnClass: 'xss_stored', cwe: 'CWE-79', endpoints: [{ path: '/api/v1/cards/9/view' }] }),
    ],
    oracleEvents: [event({ seq: 1, ts: 50 })],
  }))
  const active = ['tp', 'tp-dup', 'decoy', 'decoy-wrong-class', 'unplanted']
  const vulnMatched = s.vulns.flatMap((x) => x.matchedFindingIds)
  const decoyMatched = s.decoyResults.flatMap((x) => x.findingIds)
  const unmatched = s.unmatchedFindingIds
  assert.deepEqual([...vulnMatched].sort(), ['tp', 'tp-dup'])
  assert.deepEqual(decoyMatched, ['decoy'])
  assert.deepEqual([...unmatched].sort(), ['decoy-wrong-class', 'unplanted'])
  const union = [...vulnMatched, ...decoyMatched, ...unmatched]
  assert.equal(new Set(union).size, union.length, 'a finding was counted in two buckets')
  assert.deepEqual([...union].sort(), [...active].sort(), 'a finding vanished from accounting')
  assert.equal(s.duplicateFindings, 1)
  assert.equal(s.decoyFalsePositives, 1)
  assert.equal(s.unmatchedFalsePositives, 2)
  assert.equal(s.precision, 0.25) // 1 TP / (1 TP + 1 decoy site + 2 unmatched findings)
})

test('duplicate claims on one decoy count once', () => {
  const d = entry({ siteId: 'd' })
  const s = gradeRun(mk({
    groundTruth: gt([], [d]),
    findings: [1, 2, 3].map((i) => finding({ id: `f${i}` })),
  }))
  assert.equal(s.decoyFalsePositives, 1)
  assert.equal(s.decoyResults[0]!.findingIds.length, 3)
  assert.equal(s.precision, 0)
})

test('chain targets only count chains whose members are all vulnerable', () => {
  const a = entry({ siteId: 'a', endpoints: [GET('/a/:id', 'a.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['a.get'] } })
  const b = entry({ siteId: 'b', endpoints: [GET('/b/:id', 'b.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['b.get'] } })
  const c = entry({ siteId: 'c', endpoints: [GET('/c/:id', 'c.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['c.get'] } })
  const g = gt([a, b], [c], [
    { id: 'ab', siteIds: ['a', 'b'], severity: 'high' },
    { id: 'bc', siteIds: ['b', 'c'], severity: 'high' },
    { id: 'a', siteIds: ['a'], severity: 'high' },
  ])
  const s = gradeRun(mk({
    groundTruth: g,
    findings: [
      finding({ id: 'fa', endpoints: [{ path: '/a/1' }] }),
      finding({ id: 'fb', endpoints: [{ path: '/b/1' }] }),
    ],
    oracleEvents: [
      event({ seq: 1, ts: 50, routeKey: 'a.get', path: '/a/1' }),
      event({ seq: 2, ts: 50, routeKey: 'b.get', path: '/b/1' }),
    ],
  }))
  assert.equal(s.chainsTotal, 2, 'decoy-bearing chain must not be an unachievable target')
  assert.equal(s.chainsCompleted, 2)
})

test('recall by severity and class sums to the overall totals', () => {
  const entries = [
    entry({ siteId: 'v1', severity: 'high', vulnClass: 'bola', endpoints: [GET('/a/:id', 'a.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['a.get'] } }),
    entry({ siteId: 'v2', severity: 'medium', vulnClass: 'sqli', cwe: 'CWE-89', endpoints: [GET('/b/:id', 'b.get')], oracle: { kinds: ['sql_structure_change'], routeKeys: ['b.get'] } }),
    entry({ siteId: 'v3', severity: 'high', vulnClass: 'bola', endpoints: [GET('/c/:id', 'c.get')], oracle: { kinds: ['cross_tenant_read'], routeKeys: ['c.get'] } }),
  ]
  const s = gradeRun(mk({
    groundTruth: gt(entries),
    findings: [
      finding({ id: 'f1', endpoints: [{ path: '/a/1' }] }),
      finding({ id: 'f2', vulnClass: 'sqli', cwe: 'CWE-89', endpoints: [{ path: '/b/1' }] }),
    ],
    oracleEvents: [
      event({ seq: 1, ts: 50, routeKey: 'a.get', path: '/a/1' }),
      event({ seq: 2, ts: 50, kind: 'sql_structure_change', routeKey: 'b.get', path: '/b/1' }),
    ],
  }))
  const sev = Object.values(s.recallBySeverity)
  const cls = Object.values(s.recallByClass)
  assert.equal(sev.reduce((n, r) => n + r.targets, 0), s.targets)
  assert.equal(sev.reduce((n, r) => n + r.confirmed, 0), s.confirmed)
  assert.equal(cls.reduce((n, r) => n + r.targets, 0), s.targets)
  assert.equal(cls.reduce((n, r) => n + r.confirmed, 0), s.confirmed)
})
