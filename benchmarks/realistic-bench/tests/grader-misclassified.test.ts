// Grader accounting for class-incompatible claims, per reviewer steering:
//   1. uncharged ONLY for a documented close-sibling pair + runtime confirmation on a planted
//      vulnerable entry (never a TP, always counted in incompatibleClassCount and strictPrecision);
//   2. strictPrecision = TP / (TP + FP + misclassified), incompatibleClassCount is certificate-visible
//      and must be 0 for Phase-1;
//   3. unverified static/proposed/open-proof-gap leaks stay FPs;
//   4. non-sibling labels are charged.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type {
  GradeInput, GroundTruth, GroundTruthEntry, OracleEvent, RunTelemetry, SubmittedFinding,
} from '../lib/types.ts'
import { gradeRun } from '../grader/score.ts'
import { classKey, siblingClassPair, siblingClassPairs } from '../grader/match.ts'

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

test('sibling allowlist: documented pairs only, symmetric, CWE-only labels resolve', () => {
  for (const [a, b] of siblingClassPairs) {
    assert.ok(siblingClassPair({ vulnClass: a }, { vulnClass: b, cwe: '' }), `${a}<->${b} forward`)
    assert.ok(siblingClassPair({ vulnClass: b }, { vulnClass: a, cwe: '' }), `${a}<->${b} reverse`)
  }
  // CWE-only findings (what the harness actually submits) resolve through the taxonomy table.
  assert.equal(classKey({ cwe: 'CWE-285' }), 'bfla')
  assert.equal(classKey({ cwe: 'CWE-915' }), 'mass_assignment')
  assert.ok(siblingClassPair({ cwe: 'CWE-285' }, { vulnClass: 'mass_assignment', cwe: 'CWE-269' }))
  // Non-siblings are never forgiven.
  assert.equal(siblingClassPair({ vulnClass: 'bfla' }, { vulnClass: 'path_traversal', cwe: 'CWE-22' }), false)
  assert.equal(siblingClassPair({ vulnClass: 'xss_stored' }, { vulnClass: 'bola' }), false)
  assert.equal(siblingClassPair({ vulnClass: 'bola' }, { vulnClass: 'bola' }), false, 'identical labels are not a sibling pair')
})

test('sibling misclassification is uncharged but strict precision still charges it', () => {
  const roleTarget = entry({
    siteId: 'member-role', vulnClass: 'mass_assignment', cwe: 'CWE-269',
    endpoints: [GET('/api/v1/users/:id', 'updateMember')],
    params: ['id'],
    oracle: { kinds: ['privilege_escalation'], routeKeys: ['updateMember'] },
  })
  const s = gradeRun(mk({
    groundTruth: gt([BOLA('v'), roleTarget]),
    findings: [
      finding({ id: 'tp', vulnClass: 'bola', cwe: 'CWE-639' }),
      // CWE-only bfla claim on the mass-assignment target: sibling pair + runtime proof.
      finding({ id: 'sibling', cwe: 'CWE-285', endpoints: [{ path: '/api/v1/users/9' }] }),
    ],
    oracleEvents: [event({ seq: 1 })],
  }))
  assert.equal(s.confirmed, 1)
  assert.equal(s.unmatchedFalsePositives, 0)
  assert.deepEqual(s.misclassifiedFindingIds, ['sibling'])
  assert.equal(s.incompatibleClassCount, 1)
  assert.equal(s.precision, 1, 'standard precision leaves the documented sibling uncharged')
  assert.equal(s.strictPrecision, 0.5, 'strict precision charges it: 1 TP / (1 TP + 1 misclassified)')
  assert.equal(s.vulns.find((v) => v.siteId === 'member-role')!.outcome, 'missed', 'never a TP')
})

test('non-sibling misclassification is a charged false positive', () => {
  const traversal = entry({
    siteId: 'trav', vulnClass: 'path_traversal', cwe: 'CWE-22',
    endpoints: [GET('/api/download/:file', 'download')],
    oracle: { kinds: ['path_escape'], routeKeys: ['download'] },
  })
  const s = gradeRun(mk({
    groundTruth: gt([traversal]),
    findings: [finding({ id: 'wrong', vulnClass: 'bfla', cwe: 'CWE-863', endpoints: [{ path: '/api/download/x' }] })],
  }))
  assert.equal(s.unmatchedFalsePositives, 1, 'a non-sibling label is a false positive')
  assert.deepEqual(s.misclassifiedFindingIds, [])
  assert.equal(s.incompatibleClassCount, 1, 'still counted for the certificate')
  assert.equal(s.precision, 0)
  assert.equal(s.strictPrecision, 0)
})

test('unverified leaks stay false positives even on a sibling pair (contract leak)', () => {
  const disclosure = entry({
    siteId: 'audit', vulnClass: 'info_disclosure', cwe: 'CWE-532',
    endpoints: [GET('/api/admin/activity', 'adminAuditLog')],
    oracle: { kinds: ['secret_disclosed'], routeKeys: ['adminAuditLog'] },
  })
  for (const status of ['open_proof_gap', 'proposed', 'static_verified'] as const) {
    const s = gradeRun(mk({
      groundTruth: gt([disclosure]),
      findings: [finding({
        id: 'leak', vulnClass: 'bfla', cwe: 'CWE-863', severity: 'low',
        endpoints: [{ method: 'GET', path: '/api/admin/activity' }], status,
      })],
    }))
    assert.equal(s.unmatchedFalsePositives, 1, `${status}: an unproven leak is charged`)
    assert.deepEqual(s.misclassifiedFindingIds ?? [], [], `${status}: never uncharged`)
    assert.equal(s.incompatibleClassCount, 1)
    assert.equal(s.precision, 0)
    assert.equal(s.strictPrecision, 0)
  }
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
  assert.equal(s.incompatibleClassCount, 0, 'no vulnerable-entry endpoint was claimed')
  assert.equal(s.precision, 1 / 3)
  assert.equal(s.strictPrecision, 1 / 3)
})

test('mixed run: sibling tolerance is visible in both metrics', () => {
  const roleTarget = entry({
    siteId: 'member-role', vulnClass: 'mass_assignment', cwe: 'CWE-269',
    endpoints: [GET('/api/v1/users/:id', 'updateMember')],
    oracle: { kinds: ['privilege_escalation'], routeKeys: ['updateMember'] },
  })
  const s = gradeRun(mk({
    groundTruth: gt([BOLA('v'), roleTarget], [entry({ siteId: 'd', endpoints: [GET('/api/v1/inbox/:id', 'inbox.get')] })]),
    findings: [
      finding({ id: 'tp', vulnClass: 'bola', cwe: 'CWE-639' }),
      finding({ id: 'sibling', cwe: 'CWE-285', endpoints: [{ path: '/api/v1/users/9' }] }),
      finding({ id: 'decoy', vulnClass: 'idor', cwe: 'CWE-639', endpoints: [{ path: '/api/v1/inbox/42' }] }),
    ],
    oracleEvents: [event({ seq: 1 })],
  }))
  assert.equal(s.confirmed, 1)
  assert.equal(s.decoyFalsePositives, 1)
  assert.equal(s.unmatchedFalsePositives, 0)
  assert.deepEqual(s.misclassifiedFindingIds, ['sibling'])
  assert.equal(s.incompatibleClassCount, 1)
  assert.equal(s.precision, 0.5, '1 TP / (1 TP + 1 decoy)')
  assert.equal(s.strictPrecision, 1 / 3, '1 TP / (1 TP + 1 decoy + 1 misclassified)')
})

test('class-compatible claim without impact stays claimed_without_impact (no FP, no TP)', () => {
  const s = gradeRun(mk({
    groundTruth: gt([BOLA('v')]),
    findings: [finding({ id: 'unproven', vulnClass: 'bola', cwe: 'CWE-639' })],
  }))
  assert.equal(s.confirmed, 0)
  assert.equal(s.unmatchedFalsePositives, 0)
  assert.deepEqual(s.misclassifiedFindingIds, [])
  assert.equal(s.incompatibleClassCount, 0)
  assert.equal(s.vulns[0]!.outcome, 'claimed_without_impact')
  assert.equal(s.precision, 1)
  assert.equal(s.strictPrecision, 1)
})
