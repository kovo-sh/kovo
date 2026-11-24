/**
 * v7 shopflow false-positive triage (stream: shopflow-fp).
 *
 * The rotation smoke cell surfaced one unmatched finding: a genuine boolean/OR-branch
 * SQL-injection proof whose replay spec was correctly labelled `CWE-89` / `injection` but
 * whose persisted finding was downgraded to `CWE-200` / `information-disclosure` because the
 * impact narrative said the rows "leak". The grader then saw a class-incompatible claim on a
 * planted `sqli` target: zero recall for `product-search-sqli` plus one unmatched FP.
 *
 * These tests pin the structural fix in `oracle-invariants.ts`:
 *  - SQL injection is a first-class impact class, classified before the disclosure narrative;
 *  - evidence-class alignment keeps a `CWE-89` claim (and repairs a `CWE-200` claim) to `sqli`;
 *  - a shopflow SQLi finding then matches the planted target under the benchmark grader;
 *  - legitimate workflow/business-logic confirmations are preserved (repeat terminal transition,
 *    declared invariant event), while money/cart echoes without impact remain dismissed.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  alignClaimClass,
  assessBusinessLogicImpact,
  assessImpactEvidence,
  classifyImpactDescriptor,
  evidenceClassLabel,
  type ImpactInput,
  type ImpactStep,
} from '../src/server/oracle-invariants.ts'
import { generateVariant } from '../benchmarks/realistic-bench/generator/variant.ts'
import { buildGroundTruth } from '../benchmarks/realistic-bench/generator/groundtruth.ts'
import { blueprint } from '../benchmarks/realistic-bench/apps/shopflow/truth/blueprint.ts'
import { classCompatible, endpointMatches, matchFindingToEntries } from '../benchmarks/realistic-bench/grader/match.ts'
import type { SubmittedFinding } from '../benchmarks/realistic-bench/lib/types.ts'

const SQLI_DESCRIPTOR = {
  cwe: 'CWE-89',
  category: 'injection',
  title: 'Unauthenticated SQL injection in /api/v1/search?query= (boolean/OR-branch, cross-store data disclosure)',
  impact: 'An unauthenticated attacker controls the SQL predicate and can enumerate every store\'s wares that the store-scoped listing hides.',
}

function step(overrides: Partial<ImpactStep>): ImpactStep {
  return {
    id: overrides.id ?? 'probe',
    arm: overrides.arm ?? 'probe',
    method: overrides.method ?? 'POST',
    route: overrides.route ?? '/api/v1/bags/:cartId/coupons/reapply',
    status: overrides.status ?? 200,
    actor: overrides.actor ?? { handle: 'member_a', role: 'member', tenant: 'store-a', auth: 'cookie', sameSite: 'lax' },
    ...overrides,
  }
}

function input(steps: ImpactStep[], extra: Partial<ImpactInput> = {}): ImpactInput {
  return { impactClass: 'business_logic', steps, ...extra }
}

test('SQL injection is classified as injection, not disclosure', () => {
  assert.equal(classifyImpactDescriptor(SQLI_DESCRIPTOR), 'injection')
  // A CWE-89 claim with no narrative still classifies by CWE.
  assert.equal(classifyImpactDescriptor({ cwe: 'CWE-89', title: 'Search filter' }), 'injection')
  // A SQL-specific category works without a CWE.
  assert.equal(classifyImpactDescriptor({ category: 'sql-injection', title: 'Search filter' }), 'injection')
  // Free-text alone stays unmodelled, as before: a narrative word cannot create an ungated class.
  assert.equal(classifyImpactDescriptor({ title: 'Boolean-based SQL injection in the search filter' }), 'other')
  // Pure disclosure claims keep the disclosure class.
  assert.equal(classifyImpactDescriptor({
    cwe: 'CWE-200', category: 'information-disclosure', title: 'Tenant secret disclosed', impact: 'A secret canary is exported.',
  }), 'disclosure')
  // Workflow claims are not swallowed by the injection rule.
  assert.equal(classifyImpactDescriptor({
    cwe: 'CWE-840', category: 'business-logic', title: 'Workflow step skip', impact: 'A terminal transition was accepted twice.',
  }), 'business_logic')
})

test('evidence alignment keeps a SQLi claim (and repairs a disclosure-labelled one)', () => {
  assert.deepEqual(evidenceClassLabel('injection'), { vulnClass: 'sqli', cwe: 'CWE-89', category: 'injection' })
  // The spec's own CWE-89 is in the injection family: no destructive relabel.
  assert.equal(alignClaimClass({ cwe: 'CWE-89', category: 'injection' }, 'injection'), null)
  // If a claim was persisted as CWE-200, the injection evidence corrects it back to sqli.
  assert.deepEqual(
    alignClaimClass({ cwe: 'CWE-200', category: 'information-disclosure' }, 'injection'),
    { vulnClass: 'sqli', cwe: 'CWE-89', category: 'injection' },
  )
})

test('shopflow SQLi finding matches the planted product-search-sqli target', () => {
  const plan = generateVariant(blueprint, 1)
  const truth = buildGroundTruth(blueprint, plan)
  const target = truth.vulns.find(entry => entry.siteId === 'product-search-sqli')
  assert.ok(target, 'seed 1 must plant product-search-sqli')
  assert.equal(target.vulnClass, 'sqli')
  assert.equal(target.cwe, 'CWE-89')
  const route = target.endpoints[0]!
  const concrete = route.path.replace(/:[A-Za-z0-9_]+/g, 'probe-id')

  const finding: SubmittedFinding = {
    id: 'rb-shopflow-fp-sqli',
    title: SQLI_DESCRIPTOR.title,
    severity: 'high',
    cwe: 'CWE-89',
    endpoints: [{ method: 'GET', path: `${concrete}?query=probe` }],
    status: 'runtime_confirmed',
    submittedAtMs: 1,
    costUsdAtSubmit: 0,
  }
  const match = matchFindingToEntries(finding, truth.vulns.map(entry => ({ entry, isDecoy: false })))
  assert.equal(match?.entry.siteId, 'product-search-sqli')

  // The pre-fix label (CWE-200 from the disclosure narrative) was neither class-compatible nor a
  // documented sibling: the true positive counted as an unmatched false positive.
  const mislabelled: SubmittedFinding = { ...finding, cwe: 'CWE-200' }
  assert.equal(classCompatible(mislabelled, target), false)
  assert.equal(matchFindingToEntries(mislabelled, truth.vulns.map(entry => ({ entry, isDecoy: false }))), null)
  // Endpoint binding itself was never the problem.
  assert.ok(endpointMatches(mislabelled.endpoints[0]!, route))
})

test('legitimate workflow confirmation survives the tightened taxonomy', () => {
  const repeated = assessBusinessLogicImpact(input([
    step({ id: 'control', arm: 'control', route: '/api/v1/orders/:orderId/confirm', method: 'POST', requestJson: {} }),
    step({ id: 'probe', arm: 'probe', route: '/api/v1/orders/:orderId/confirm', method: 'POST', requestJson: {} }),
  ]))
  assert.equal(repeated.satisfied, true)
  assert.match(repeated.reason, /accepted a second time/)

  // A persisted protected financial field that the probe itself sent is still impact.
  const persisted = assessBusinessLogicImpact(input([
    step({ id: 'before', method: 'GET', route: '/api/v1/giftcards/:id', json: { balance: 100 } }),
    step({ id: 'probe', method: 'PATCH', route: '/api/v1/giftcards/:id', requestJson: { balance: 999 }, json: { ok: true } }),
    step({ id: 'after', method: 'GET', route: '/api/v1/giftcards/:id', json: { balance: 999 } }),
  ]))
  assert.equal(persisted.satisfied, true)
  assert.ok(persisted.evidence.protectedFields.includes('balance'))
})

test('money/cart echoes without impact are still dismissed', () => {
  const echo = assessImpactEvidence(input([
    step({ id: 'apply', method: 'POST', route: '/api/v1/bags/:cartId/coupons', requestJson: { couponCode: 'WELCOME10' }, json: { ok: true, discount: 1000 } }),
  ]))
  assert.equal(echo.satisfied, false)

  const collision = assessImpactEvidence(input([
    step({ id: 'before', method: 'GET', route: '/api/v1/bags/:cartId', json: { amount: 1200 } }),
    step({ id: 'probe', method: 'POST', route: '/api/v1/bags/:cartId/items', requestJson: { qty: 7, lineNote: 'probe-line-zzz' }, json: { ok: true } }),
    step({ id: 'after', method: 'GET', route: '/api/v1/bags/:cartId', json: { amount: 9900 } }),
  ]))
  assert.equal(collision.satisfied, false)
  assert.match(collision.reason, /cannot be excluded/)
})
