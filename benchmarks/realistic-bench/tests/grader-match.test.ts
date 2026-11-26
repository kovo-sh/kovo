// Match-layer unit tests: path normalization, CWE-family + vulnClass-alias, best-match tie-break.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { GroundTruthEntry, SubmittedFinding } from '../lib/types.ts'
import {
  classCompatible, endpointMatches, matchFindingToEntries, normalizePath,
} from '../grader/match.ts'
import type { GradeEntry } from '../grader/match.ts'

function entry(over: Partial<GroundTruthEntry> & { siteId: string }): GroundTruthEntry {
  return {
    siteId: over.siteId,
    title: over.title ?? over.siteId,
    vulnClass: over.vulnClass ?? 'idor',
    cwe: over.cwe ?? 'CWE-639',
    severity: over.severity ?? 'high',
    endpoints: over.endpoints ?? [{ method: 'GET', path: '/api/v1/invoices/:id', routeKey: 'invoice.get' }],
    triggerEndpoints: over.triggerEndpoints ?? over.endpoints ?? [{ method: 'GET', path: '/api/v1/invoices/:id', routeKey: 'invoice.get' }],
    params: over.params ?? ['id'],
    oracle: over.oracle ?? { kinds: ['cross_tenant_read'], routeKeys: ['invoice.get'] },
    rootCause: over.rootCause ?? { file: 'billing/invoices.ts', symbol: 'getInvoice' },
    chain: over.chain,
    formEncoding: over.formEncoding,
    requiresCsrf: over.requiresCsrf,
    secondOrder: over.secondOrder,
    lure: over.lure,
  }
}

function finding(over: Partial<SubmittedFinding> & { id: string }): SubmittedFinding {
  return {
    id: over.id,
    title: over.title ?? over.id,
    cwe: over.cwe,
    vulnClass: over.vulnClass,
    severity: over.severity,
    endpoints: over.endpoints ?? [{ method: 'GET', path: '/api/v1/invoices/42' }],
    params: over.params,
    status: over.status ?? 'runtime_confirmed',
    submittedAtMs: over.submittedAtMs ?? 100,
    costUsdAtSubmit: over.costUsdAtSubmit,
    codeLocations: over.codeLocations,
  }
}

test('normalizePath strips origin and query, collapses trailing slash', () => {
  assert.equal(normalizePath('http://127.0.0.1:53211/api/v1/invoices/42?x=1#f'), '/api/v1/invoices/42')
  assert.equal(normalizePath('/api/v1/invoices/42/'), '/api/v1/invoices/42')
  assert.equal(normalizePath('api/x'), '/api/x')
})

test('endpointMatches: concrete vs :param vs templated vs full URL', () => {
  const route = { method: 'GET', path: '/api/v1/invoices/:id' }
  assert.ok(endpointMatches({ path: '/api/v1/invoices/42' }, route))
  assert.ok(endpointMatches({ path: '/api/v1/invoices/{id}' }, route))
  assert.ok(endpointMatches({ path: '/api/v1/invoices/:id' }, route))
  assert.ok(endpointMatches({ path: '/api/v1/invoices/<id>' }, route))
  assert.ok(endpointMatches({ path: 'http://127.0.0.1:9000/api/v1/invoices/42?a=b' }, route))
  assert.ok(!endpointMatches({ path: '/api/v1/orders/42' }, route))
  assert.ok(!endpointMatches({ path: '/api/v1/invoices/42/extra' }, route))
})

test('endpointMatches: method optional but conflicting methods fail', () => {
  const route = { method: 'POST', path: '/a/b' }
  assert.ok(endpointMatches({ path: '/a/b' }, route))
  assert.ok(endpointMatches({ method: 'post', path: '/a/b' }, route))
  assert.ok(!endpointMatches({ method: 'GET', path: '/a/b' }, route))
})

test('classCompatible: exact class, CWE-family, alias, and missing class', () => {
  const e = entry({ siteId: 's', vulnClass: 'bola', cwe: 'CWE-639' })
  assert.ok(classCompatible({ vulnClass: 'bola' }, e)) // exact
  assert.ok(classCompatible({ cwe: 'CWE-285' }, e)) // same authz family
  assert.ok(classCompatible({ vulnClass: 'idor' }, e)) // alias -> authz
  assert.ok(!classCompatible({}, e)) // missing class -> fail closed (cq-1)
  assert.ok(!classCompatible({ vulnClass: 'sqli' }, e))
  assert.ok(!classCompatible({ cwe: 'CWE-89' }, e))
})

test('classCompatible: SQLi family and XSS family', () => {
  const sq = entry({ siteId: 'q', vulnClass: 'sqli', cwe: 'CWE-89' })
  assert.ok(classCompatible({ cwe: 'CWE-564' }, sq))
  const xs = entry({ siteId: 'x', vulnClass: 'xss_stored', cwe: 'CWE-79' })
  assert.ok(classCompatible({ vulnClass: 'xss_reflected' }, xs))
  assert.ok(classCompatible({ cwe: 'CWE-80' }, xs))
})

test('matchFindingToEntries: ties prefer vuln over decoy', () => {
  const vuln: GradeEntry = { entry: entry({ siteId: 'vuln', vulnClass: 'bola' }), isDecoy: false }
  const decoy: GradeEntry = { entry: entry({ siteId: 'decoy', vulnClass: 'bola' }), isDecoy: true }
  const m = matchFindingToEntries(finding({ id: 'f', vulnClass: 'bola' }), [decoy, vuln])
  assert.ok(m)
  assert.equal(m.entry.siteId, 'vuln')
  assert.equal(m.isDecoy, false)
})

test('matchFindingToEntries: no match returns null', () => {
  const vuln: GradeEntry = { entry: entry({ siteId: 'vuln' }), isDecoy: false }
  const m = matchFindingToEntries(finding({ id: 'f', vulnClass: 'sqli', endpoints: [{ path: '/nope' }] }), [vuln])
  assert.equal(m, null)
})
