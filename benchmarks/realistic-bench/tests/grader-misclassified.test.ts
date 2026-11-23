// Grader accounting: a class-incompatible claim on a *planted vulnerable* endpoint is a misclassified
// location hit — the endpoint is not clean, so it must not be charged as a false positive, and it must
// never earn recall. Claims on decoys or unknown endpoints stay false positives.
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

function gt(vulns: GroundTruthEntry[], decoys: GroundTruthEntry[] = []): GroundTruth {
  return { schemaVersion: 1, app: 'acme-saas', seed: 1, seedSet: 'dev', vulns, decoys, chains: [] }
}

function mk(o: Partial<GradeInput> & { groundTruth: GroundTruth }): GradeInput {
  return {
    groundTruth: o.groundTruth, findings: o.findings ?? [], oracleEvents: o.oracleEvents ?? [],
    requestLog: o.requestLog ?? [], egressLog: o.egressLog, telemetry: o.telemetry ?? tel(), mode: o.mode ?? 'grey-box',
  }
}

const BOLA = (siteId: string): GroundTruthEntry => entry({ siteId })

test('class-incompatible claim on a vulnerable endpoint is uncharged, not a TP', () => {
  const s = gradeRun(mk({
    groundTruth: gt([BOLA('v')]),
    findings: [finding({ id: 'misfiled', vulnClass: 'xss_stored', cwe: 'CWE-79' })],
    oracleEvents: [event({ seq: 1 })],
  }))
  assert.equal(s.confirmed, 0, 'wrong class never earns recall')
  assert.equal(s.unmatchedFalsePositives, 0, 'the endpoint is not clean')
  assert.equal(s.decoyFalsePositives, 0)
  assert.deepEqual(s.misclassifiedFindingIds, ['misfiled'])
  assert.equal(s.precision, 1, 'no false alarm is charged')
  assert.equal(s.funnel.specSubmitted, 0, 'a misclassified hit is not a submitted spec for the target')
})

test('misclassified hit is reported but never counted as confirmed even with an oracle event', () => {
  const s = gradeRun(mk({
    groundTruth: gt([BOLA('v')]),
    // Route-level hit on the target endpoint with a label from another class family.
    findings: [finding({ id: 'misfiled', vulnClass: 'sqli', cwe: 'CWE-89', endpoints: [{ path: '/api/v1/invoices/42' }] })],
    oracleEvents: [event({ seq: 1 }), event({ seq: 2, kind: 'privilege_escalation' })],
  }))
  assert.equal(s.confirmed, 0)
  assert.equal(s.vulns[0]!.outcome, 'missed')
  assert.equal(s.precision, 1)
  assert.deepEqual(s.misclassifiedFindingIds, ['misfiled'])
})

test('claims on decoy and unknown endpoints remain false positives', () => {
  const s = gradeRun(mk({
    groundTruth: gt([BOLA('v')], [entry({ siteId: 'd', endpoints: [GET('/api/v1/inbox/:id', 'inbox.get')] })]),
    findings: [
      finding({ id: 'wrong-class-decoy', vulnClass: 'xss_stored', cwe: 'CWE-79', endpoints: [{ path: '/api/v1/inbox/42' }] }),
      finding({ id: 'unknown', vulnClass: 'bola', cwe: 'CWE-639', endpoints: [{ path: '/api/v1/nothing/42' }] }),
      finding({ id: 'on-target', vulnClass: 'bola', cwe: 'CWE-639' }),
    ],
    oracleEvents: [event({ seq: 1 })],
  }))
  assert.equal(s.confirmed, 1, 'the class-compatible claim confirms')
  assert.equal(s.unmatchedFalsePositives, 2, 'decoy + unknown endpoint claims are charged')
  assert.equal(s.decoyFalsePositives, 0, 'wrong-class decoy claim is charged as unmatched, not twice')
  assert.deepEqual(s.misclassifiedFindingIds, [])
  assert.equal(s.precision, 1 / 3)
})

test('mixed run: misclassified does not enter the precision denominator', () => {
  const s = gradeRun(mk({
    groundTruth: gt([BOLA('v')], [entry({ siteId: 'd', endpoints: [GET('/api/v1/inbox/:id', 'inbox.get')] })]),
    findings: [
      finding({ id: 'tp', vulnClass: 'bola', cwe: 'CWE-639' }),
      finding({ id: 'misfiled', vulnClass: 'xss_stored', cwe: 'CWE-79' }),
      finding({ id: 'decoy', vulnClass: 'idor', cwe: 'CWE-639', endpoints: [{ path: '/api/v1/inbox/42' }] }),
    ],
    oracleEvents: [event({ seq: 1 })],
  }))
  assert.equal(s.confirmed, 1)
  assert.equal(s.decoyFalsePositives, 1)
  assert.equal(s.unmatchedFalsePositives, 0)
  assert.deepEqual(s.misclassifiedFindingIds, ['misfiled'])
  assert.equal(s.precision, 0.5)
})

test('class-compatible claim without impact stays claimed_without_impact (no FP, no TP)', () => {
  const s = gradeRun(mk({
    groundTruth: gt([BOLA('v')]),
    findings: [finding({ id: 'unproven', vulnClass: 'bola', cwe: 'CWE-639' })],
  }))
  assert.equal(s.confirmed, 0)
  assert.equal(s.unmatchedFalsePositives, 0)
  assert.deepEqual(s.misclassifiedFindingIds, [])
  assert.equal(s.vulns[0]!.outcome, 'claimed_without_impact')
  assert.equal(s.precision, 1)
})

test('rule-check claim on a disclosure target endpoint is uncharged (audit-log case)', () => {
  const auditLog = entry({
    siteId: 'audit', vulnClass: 'info_disclosure', cwe: 'CWE-532',
    endpoints: [GET('/api/admin/activity', 'adminAuditLog')],
    oracle: { kinds: ['secret_disclosed'], routeKeys: ['adminAuditLog'] },
  })
  const s = gradeRun(mk({
    groundTruth: gt([auditLog]),
    findings: [finding({
      id: 'bfla-note', vulnClass: 'bfla', cwe: 'CWE-863', severity: 'low',
      endpoints: [{ method: 'GET', path: '/api/admin/activity' }], status: 'open_proof_gap',
    })],
  }))
  assert.equal(s.confirmed, 0, 'the claim is not a disclosure confirmation')
  assert.equal(s.unmatchedFalsePositives, 0, 'the endpoint is a planted vulnerable target')
  assert.deepEqual(s.misclassifiedFindingIds, ['bfla-note'])
  assert.equal(s.precision, 1)
})
