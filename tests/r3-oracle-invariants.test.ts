/**
 * R3-C-2 & R3-C-4 (kernel-side) regression suite for `src/server/oracle-invariants.ts`:
 *  - R3-C-2: `business_logic` repeated transitions exclude volatile metadata, require a genuine
 *    semantic double effect, enforce the same-object stale-404 rule, and never short-circuit
 *    without a boundary or invariant signal.
 *  - R3-C-4: Boolean-differential and status-boolean triangles parse predicates strictly from
 *    the named injected parameter and enforce byte-identical base-value binding against the
 *    baseline arm (closing integer-coercion bypasses).
 *
 * Defensive QA framing: pure in-memory differential verification fixtures only.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, test } from 'node:test'

import {
  assessBooleanDifferential,
  assessBusinessLogicImpact,
  assessInjectionImpact,
  booleanPredicateTruth,
  parseBooleanPredicate,
  stateDelta,
  verifyBooleanTriangleBinding,
  type ActorIdentity,
  type BooleanDifferentialRound,
  type ImpactStep,
} from '../src/server/oracle-invariants.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)
const memberAcme: ActorIdentity = { handle: 'member_a', role: 'member', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }
const viewerAcme: ActorIdentity = { handle: 'viewer_a', role: 'viewer', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }

function makeStep(overrides: Partial<ImpactStep> = {}): ImpactStep {
  return {
    id: overrides.id ?? 'step',
    arm: overrides.arm ?? 'probe',
    method: overrides.method ?? 'GET',
    route: overrides.route ?? '/api/items/1',
    status: overrides.status ?? 200,
    actor: overrides.actor ?? memberAcme,
    ...overrides,
  }
}

// ===========================================================================
// 1. R3-C-2: business_logic repeated transitions & volatile metadata exclusion
// ===========================================================================

describe('R3-C-2: business_logic volatile-field exclusion, semantic double effect, and stale-404 rule', () => {
  test('stateDelta excludes volatile metadata leaves by default and scopes to allowed/invariant fields when requested', () => {
    const volatileLeaves = [
      'updated_at', 'updatedAt', 'modified_at', 'modifiedAt', 'last_modified', 'lastModified',
      'version', 'etag', 'eTag', 'rev', 'revision', 'timestamp', 'ts',
      'request_id', 'requestId', 'trace_id', 'traceId', 'update_count', 'monotonic_counter', '__v',
    ]
    for (const leaf of volatileLeaves) {
      const topDelta = stateDelta({ id: '1', [leaf]: 'a' }, { id: '1', [leaf]: 'b' }, 200)
      assert.deepEqual(topDelta.changed, [], `expected volatile leaf excluded: ${leaf}`)
      const nestedDelta = stateDelta({ meta: { [leaf]: 'a' } }, { meta: { [leaf]: 'b' } }, 200)
      assert.deepEqual(nestedDelta.changed, [], `expected volatile nested leaf excluded: meta.${leaf}`)
    }

    const before = {
      id: '1',
      title: 'same',
      updated_at: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
      modified_at: '2026-01-01T00:00:00Z',
      last_modified: '2026-01-01T00:00:00Z',
      version: 1,
      etag: '"v1"',
      rev: '1-aaa',
      revision: 1,
      timestamp: 1000,
      ts: 1000,
      request_id: 'req-1',
      requestId: 'req-1',
      trace_id: 'tr-1',
      update_count: 1,
      __v: 0,
    }
    const after = {
      id: '1',
      title: 'same',
      updated_at: '2026-01-01T00:00:05Z',
      updatedAt: '2026-01-01T00:00:05Z',
      modified_at: '2026-01-01T00:00:05Z',
      last_modified: '2026-01-01T00:00:05Z',
      version: 2,
      etag: '"v2"',
      rev: '2-bbb',
      revision: 2,
      timestamp: 2000,
      ts: 2000,
      request_id: 'req-2',
      requestId: 'req-2',
      trace_id: 'tr-2',
      update_count: 2,
      __v: 1,
    }
    const delta = stateDelta(before, after, 200)
    assert.deepEqual(delta.changed, [])
    assert.deepEqual(delta.added, [])
    assert.deepEqual(delta.removed, [])
    assert.equal(delta.deleted, false)
  })

  test('rejects idempotent PUT twice with updated_at / version / etag churn between readbacks', () => {
    const res = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({
          id: 'r0', arm: 'control', method: 'GET', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 200,
          json: { id: '1', title: 'initial', updated_at: '2026-01-01T00:00:00Z', version: 1, etag: '"a"' },
        }),
        makeStep({
          id: 't1', arm: 'control', method: 'PUT', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 200,
          requestJson: { title: 'updated' }, json: { ok: true },
        }),
        makeStep({
          id: 'r1', arm: 'control', method: 'GET', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 200,
          json: { id: '1', title: 'updated', updated_at: '2026-01-01T00:00:01Z', version: 2, etag: '"b"' },
        }),
        makeStep({
          id: 't2', arm: 'probe', method: 'PUT', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 200,
          requestJson: { title: 'updated' }, json: { ok: true },
        }),
        makeStep({
          id: 'r2', arm: 'control', method: 'GET', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 200,
          json: { id: '1', title: 'updated', updated_at: '2026-01-01T00:00:02Z', version: 3, etag: '"c"' },
        }),
      ],
    })
    assert.equal(res.satisfied, false, res.reason)
    assert.equal(res.evidence.repeatedTransition, false)
    assert.equal(res.evidence.boundary, false)
    assert.deepEqual(res.evidence.protectedFields, [])
  })

  test('rejects idempotent PUT twice even if an uncited concurrent write mutates a non-invariant CRUD field', () => {
    const res = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', arm: 'control', method: 'GET', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 200, json: { id: '1', title: 'v1' } }),
        makeStep({ id: 't1', arm: 'control', method: 'PUT', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 200, requestJson: { title: 'v2' }, json: { ok: true } }),
        makeStep({ id: 'r1', arm: 'control', method: 'GET', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 200, json: { id: '1', title: 'v2' } }),
        makeStep({ id: 't2', arm: 'probe', method: 'PUT', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 200, requestJson: { title: 'v2' }, json: { ok: true } }),
        makeStep({ id: 'r2', arm: 'control', method: 'GET', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 200, json: { id: '1', title: 'v3-from-other-writer' } }),
      ],
    })
    assert.equal(res.satisfied, false, res.reason)
    assert.equal(res.evidence.repeatedTransition, false)
  })

  test('rejects idempotent DELETE twice (204/204) with collection read between and item 404 afterwards (stale-404 rule)', () => {
    const res = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', arm: 'control', method: 'GET', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 200, json: { id: '1', title: 'alpha' } }),
        makeStep({ id: 'd1', arm: 'control', method: 'DELETE', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 204 }),
        makeStep({ id: 'r1', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items', status: 200, json: { items: [] } }),
        makeStep({ id: 'd2', arm: 'probe', method: 'DELETE', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 204 }),
        makeStep({ id: 'r2', arm: 'control', method: 'GET', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 404 }),
      ],
    })
    assert.equal(res.satisfied, false, res.reason)
    assert.equal(res.evidence.repeatedTransition, false)

    // Also reject when the intermediate read on the same item is already 404.
    const alreadyGone = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', arm: 'control', method: 'GET', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 200, json: { id: '1', title: 'alpha' } }),
        makeStep({ id: 'd1', arm: 'control', method: 'DELETE', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 204 }),
        makeStep({ id: 'r1', arm: 'control', method: 'GET', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 404 }),
        makeStep({ id: 'd2', arm: 'probe', method: 'DELETE', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 204 }),
        makeStep({ id: 'r2', arm: 'control', method: 'GET', route: '/api/items/1', pathAndQuery: '/api/items/1', status: 404 }),
      ],
    })
    assert.equal(alreadyGone.satisfied, false, alreadyGone.reason)
    assert.equal(alreadyGone.evidence.repeatedTransition, false)
  })

  test('confirms genuine repeated business-logic transitions with semantic double effect (balance decrement, coupon double-redeem, cumulative ledger, host-declared invariant)', () => {
    // 1. Balance double-decrement alongside volatile updated_at/version churn
    const doubleWithdraw = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', arm: 'control', method: 'GET', route: '/api/wallets/w-7', pathAndQuery: '/api/wallets/w-7', status: 200, json: { id: 'w-7', balance: 1000, updated_at: 'T0', version: 1 } }),
        makeStep({ id: 't1', arm: 'probe', method: 'POST', route: '/api/wallets/w-7/withdraw', pathAndQuery: '/api/wallets/w-7/withdraw', status: 200, requestJson: { amount: 600 }, json: { ok: true } }),
        makeStep({ id: 'r1', arm: 'control', method: 'GET', route: '/api/wallets/w-7', pathAndQuery: '/api/wallets/w-7', status: 200, json: { id: 'w-7', balance: 400, updated_at: 'T1', version: 2 } }),
        makeStep({ id: 't2', arm: 'probe', method: 'POST', route: '/api/wallets/w-7/withdraw', pathAndQuery: '/api/wallets/w-7/withdraw', status: 200, requestJson: { amount: 600 }, json: { ok: true } }),
        makeStep({ id: 'r2', arm: 'control', method: 'GET', route: '/api/wallets/w-7', pathAndQuery: '/api/wallets/w-7', status: 200, json: { id: 'w-7', balance: -200, updated_at: 'T2', version: 3 } }),
      ],
    })
    assert.equal(doubleWithdraw.satisfied, true, doubleWithdraw.reason)
    assert.equal(doubleWithdraw.evidence.repeatedTransition, true)
    assert.ok(doubleWithdraw.evidence.protectedFields.includes('balance'))

    // 2. Coupon double-redeem with cumulative applied_coupons array growth + discount shift
    const couponDoubleRedeem = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      steps: [
        makeStep({ id: 'r0', arm: 'control', method: 'GET', route: '/api/carts/cart-9', pathAndQuery: '/api/carts/cart-9', status: 200, json: { id: 'cart-9', discount_cents: 0, applied_coupons: [] } }),
        makeStep({ id: 't1', arm: 'probe', method: 'POST', route: '/api/carts/cart-9/coupons', pathAndQuery: '/api/carts/cart-9/coupons', status: 200, requestJson: { code: 'SAVE20' }, json: { ok: true } }),
        makeStep({ id: 'r1', arm: 'control', method: 'GET', route: '/api/carts/cart-9', pathAndQuery: '/api/carts/cart-9', status: 200, json: { id: 'cart-9', discount_cents: 2000, applied_coupons: ['SAVE20'] } }),
        makeStep({ id: 't2', arm: 'probe', method: 'POST', route: '/api/carts/cart-9/coupons', pathAndQuery: '/api/carts/cart-9/coupons', status: 200, requestJson: { code: 'SAVE20' }, json: { ok: true } }),
        makeStep({ id: 'r2', arm: 'control', method: 'GET', route: '/api/carts/cart-9', pathAndQuery: '/api/carts/cart-9', status: 200, json: { id: 'cart-9', discount_cents: 4000, applied_coupons: ['SAVE20', 'SAVE20'] } }),
      ],
    })
    assert.equal(couponDoubleRedeem.satisfied, true, couponDoubleRedeem.reason)
    assert.equal(couponDoubleRedeem.evidence.repeatedTransition, true)

    // 3. Host-declared invariant field cumulative shift
    const hostDeclared = assessBusinessLogicImpact({
      impactClass: 'business_logic',
      invariantFields: ['custom_tally'],
      steps: [
        makeStep({ id: 'r0', arm: 'control', method: 'GET', route: '/api/tasks/tsk-1', pathAndQuery: '/api/tasks/tsk-1', status: 200, json: { id: 'tsk-1', custom_tally: 0 } }),
        makeStep({ id: 't1', arm: 'probe', method: 'POST', route: '/api/tasks/tsk-1/claim', pathAndQuery: '/api/tasks/tsk-1/claim', status: 200, requestJson: {}, json: { ok: true } }),
        makeStep({ id: 'r1', arm: 'control', method: 'GET', route: '/api/tasks/tsk-1', pathAndQuery: '/api/tasks/tsk-1', status: 200, json: { id: 'tsk-1', custom_tally: 5 } }),
        makeStep({ id: 't2', arm: 'probe', method: 'POST', route: '/api/tasks/tsk-1/claim', pathAndQuery: '/api/tasks/tsk-1/claim', status: 200, requestJson: {}, json: { ok: true } }),
        makeStep({ id: 'r2', arm: 'control', method: 'GET', route: '/api/tasks/tsk-1', pathAndQuery: '/api/tasks/tsk-1', status: 200, json: { id: 'tsk-1', custom_tally: 10 } }),
      ],
    })
    assert.equal(hostDeclared.satisfied, true, hostDeclared.reason)
    assert.equal(hostDeclared.evidence.repeatedTransition, true)
  })
})

// ===========================================================================
// 2. R3-C-4: Boolean-differential & status-boolean base-value binding
// ===========================================================================

describe('R3-C-4: boolean-differential and status-boolean base-value binding', () => {
  function queryTriangle(baseId: string, trueId: string, falseId: string, opts?: {
    trueStatus?: number
    falseStatus?: number
    trueJson?: unknown
    falseJson?: unknown
  }): BooleanDifferentialRound {
    return {
      baseline: {
        status: 200,
        method: 'GET',
        origin: 'https://app.example.test',
        persona: 'viewer_a',
        pathAndQuery: `/api/items?id=${encodeURIComponent(baseId)}`,
        json: { id: 42, name: 'Widget' },
      },
      control: {
        status: opts?.trueStatus ?? 200,
        method: 'GET',
        origin: 'https://app.example.test',
        persona: 'viewer_a',
        pathAndQuery: `/api/items?id=${encodeURIComponent(trueId)}`,
        json: opts?.trueJson ?? { id: 42, name: 'Widget' },
      },
      probe: {
        status: opts?.falseStatus ?? 404,
        method: 'GET',
        origin: 'https://app.example.test',
        persona: 'viewer_a',
        pathAndQuery: `/api/items?id=${encodeURIComponent(falseId)}`,
        json: opts?.falseJson ?? { error: 'not found' },
      },
    }
  }

  test('parseBooleanPredicate extracts byte-exact base values and rejects bare/compound/garbage inputs', () => {
    const p1 = parseBooleanPredicate('42 AND 1=1')
    assert.deepEqual({ base: p1?.baseValue, delim: p1?.quoteDelimiter, truth: p1?.truth }, { base: '42', delim: '', truth: true })

    const p2 = parseBooleanPredicate("abc' AND 1=2-- -")
    assert.deepEqual({ base: p2?.baseValue, delim: p2?.quoteDelimiter, truth: p2?.truth }, { base: 'abc', delim: "'", truth: false })

    const p3 = parseBooleanPredicate("item--1' AND 'a'='a")
    assert.deepEqual({ base: p3?.baseValue, delim: p3?.quoteDelimiter, truth: p3?.truth }, { base: 'item--1', delim: "'", truth: true })

    const p4 = parseBooleanPredicate("abc'/**/AND/**/7919=7919--")
    assert.deepEqual({ base: p4?.baseValue, delim: p4?.quoteDelimiter, truth: p4?.truth }, { base: 'abc', delim: "'", truth: true })

    const p5 = parseBooleanPredicate('42 AND NOT FALSE')
    assert.deepEqual({ base: p5?.baseValue, delim: p5?.quoteDelimiter, truth: p5?.truth }, { base: '42', delim: '', truth: true })

    assert.equal(parseBooleanPredicate('1'), null)
    assert.equal(parseBooleanPredicate('0'), null)
    assert.equal(parseBooleanPredicate('true'), null)
    assert.equal(parseBooleanPredicate('false'), null)
    assert.equal(parseBooleanPredicate('42 AND 1=1 AND 1=2'), null)
    assert.equal(parseBooleanPredicate('42 AND 1=1 trailing_garbage'), null)
    assert.equal(booleanPredicateTruth('1'), null)
    assert.equal(booleanPredicateTruth('7919=7919'), true)
    assert.equal(booleanPredicateTruth('7919=7920'), false)
  })

  test('rejects integer-coercion boolean-differential triangle (existing ID vs missing ID) in BOTH assessBooleanDifferential and statusBoolean', () => {
    // Integer-coercion stub: parseInt(id) === 42 -> 200, else 404.
    const coercionRound = queryTriangle('42', '42 AND 1=1', '999999 AND 1=2')
    const diffRes = assessBooleanDifferential({
      param: 'id',
      rounds: [coercionRound, coercionRound],
    })
    assert.equal(diffRes.satisfied, false, diffRes.reason)
    assert.equal(diffRes.evidence.baseBindingMismatch, true)

    // Quoted variant with differing base IDs
    const quotedCoercion = queryTriangle('42', "42' AND 1=1-- -", "999999' AND 1=2-- -")
    assert.equal(assessBooleanDifferential({ param: 'id', rounds: [quotedCoercion, quotedCoercion] }).satisfied, false)

    // Standalone predicate coercion (`id=42` baseline, `id=42=42` true, `id=999999=0` false)
    const standaloneCoercion = queryTriangle('42', '42=42', '999999=0')
    assert.equal(assessBooleanDifferential({ param: 'id', rounds: [standaloneCoercion, standaloneCoercion] }).satisfied, false)

    // Empty-baseline leading-operand coercion (`id=` baseline, `id=1=1` true, `id=999999=0` false)
    const emptyBaseCoercion = queryTriangle('', '1=1', '999999=0')
    assert.equal(assessBooleanDifferential({ param: 'id', rounds: [emptyBaseCoercion, emptyBaseCoercion] }).satisfied, false)

    // Baseline differs from shared true/false base (`baseline=42`, `true=7 AND 1=1`, `false=7 AND 1=2`)
    const baselineMismatch = queryTriangle('42', '7 AND 1=1', '7 AND 1=2')
    assert.equal(assessBooleanDifferential({ param: 'id', rounds: [baselineMismatch, baselineMismatch] }).satisfied, false)

    // Mismatched quote breakout delimiter (`42 AND 1=1` vs `42' AND 1=2`)
    const quoteMismatch = queryTriangle('42', '42 AND 1=1', "42' AND 1=2")
    assert.equal(assessBooleanDifferential({ param: 'id', rounds: [quoteMismatch, quoteMismatch] }).satisfied, false)

    // statusBoolean: same integer-coercion triangle (200 / 200 / 404), both with and without explicit param
    const benign = makeStep({ id: 'b', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=42', status: 200, actor: viewerAcme })
    const tautology = makeStep({ id: 't', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=42%20AND%201%3D1', status: 200, actor: viewerAcme })
    const contradiction = makeStep({ id: 'f', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=999999%20AND%201%3D2', status: 404, actor: viewerAcme })

    const sbImplicit = assessInjectionImpact({
      impactClass: 'injection',
      steps: [benign, tautology, contradiction],
      injection: { family: 'sqli', statusBoolean: { benign, tautology, contradiction } },
    })
    assert.equal(sbImplicit.satisfied, false, sbImplicit.reason)

    const sbExplicit = assessInjectionImpact({
      impactClass: 'injection',
      steps: [benign, tautology, contradiction],
      injection: { family: 'sqli', param: 'id', statusBoolean: { benign, tautology, contradiction, param: 'id' } },
    })
    assert.equal(sbExplicit.satisfied, false, sbExplicit.reason)

    // statusBoolean: raw-request smuggling where predicate sits in another param (`note`) while `id` changes
    const smuggleBenign = makeStep({ id: 'sb', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=42&note=hi', status: 200, actor: viewerAcme })
    const smuggleTrue = makeStep({ id: 'st', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=42&note=hi%20AND%201%3D1', status: 200, actor: viewerAcme })
    const smuggleFalse = makeStep({ id: 'sf', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=999999&note=hi%20AND%201%3D2', status: 404, actor: viewerAcme })
    const sbSmuggle = assessInjectionImpact({
      impactClass: 'injection',
      steps: [smuggleBenign, smuggleTrue, smuggleFalse],
      injection: { family: 'sqli', statusBoolean: { benign: smuggleBenign, tautology: smuggleTrue, contradiction: smuggleFalse } },
    })
    assert.equal(sbSmuggle.satisfied, false, sbSmuggle.reason)
  })

  test('confirms same-base boolean-differential and statusBoolean triangles (query, JSON, and path segment) and exposes shared binding helper', () => {
    // 1. Query param with identical numeric base
    const sameNum = queryTriangle('42', '42 AND 7919=7919', '42 AND 7919=7920')
    const numRes = assessBooleanDifferential({ param: 'id', rounds: [sameNum, sameNum] })
    assert.equal(numRes.satisfied, true, numRes.reason)
    assert.equal(numRes.evidence.baseBindingMismatch, false)

    // 2. Query param with identical quoted string base
    const sameStr = queryTriangle('widget', "widget' AND 7919=7919-- -", "widget' AND 7919=7920-- -")
    const strRes = assessBooleanDifferential({ param: 'id', rounds: [sameStr, sameStr] })
    assert.equal(strRes.satisfied, true, strRes.reason)

    // 3. statusBoolean with identical base across benign / tautology / contradiction
    const benign = makeStep({ id: 'b', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=42', status: 200, actor: viewerAcme })
    const tautology = makeStep({ id: 't', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=42%20AND%201%3D1', status: 200, actor: viewerAcme })
    const contradiction = makeStep({ id: 'f', arm: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?id=42%20AND%201%3D2', status: 404, actor: viewerAcme })
    const sbRes = assessInjectionImpact({
      impactClass: 'injection',
      steps: [benign, tautology, contradiction],
      injection: { family: 'sqli', statusBoolean: { benign, tautology, contradiction } },
    })
    assert.equal(sbRes.satisfied, true, sbRes.reason)
    assert.equal(sbRes.evidence?.statusBoolean, true)

    // 4. Path-segment triangle: same base confirms, integer-coercion different base rejects
    const pathSameRound: BooleanDifferentialRound = {
      baseline: { status: 200, method: 'GET', origin: 'https://app.example.test', persona: 'viewer_a', pathAndQuery: '/api/items/42', json: { id: 42, name: 'Widget' } },
      control: { status: 200, method: 'GET', origin: 'https://app.example.test', persona: 'viewer_a', pathAndQuery: '/api/items/42%20AND%201%3D1', json: { id: 42, name: 'Widget' } },
      probe: { status: 404, method: 'GET', origin: 'https://app.example.test', persona: 'viewer_a', pathAndQuery: '/api/items/42%20AND%201%3D2', json: { error: 'not found' } },
    }
    assert.equal(assessBooleanDifferential({ param: 'id', rounds: [pathSameRound, pathSameRound] }).satisfied, true)

    const pathCoercionRound: BooleanDifferentialRound = {
      ...pathSameRound,
      probe: { status: 404, method: 'GET', origin: 'https://app.example.test', persona: 'viewer_a', pathAndQuery: '/api/items/999%20AND%201%3D2', json: { error: 'not found' } },
    }
    assert.equal(assessBooleanDifferential({ param: 'id', rounds: [pathCoercionRound, pathCoercionRound] }).satisfied, false)

    // 5. Direct shared binding helper export for proof-receipt.ts / verify-rpc.ts reuse
    const bound = verifyBooleanTriangleBinding({
      baseline: sameStr.baseline!,
      armA: sameStr.control,
      armB: sameStr.probe,
      param: 'id',
    })
    assert.equal(bound.ok, true)
    assert.equal(bound.baseValue, 'widget')
    assert.equal(bound.trueArm, 'armA')
  })

  test('oracle-invariants.ts keeps zero dynamic new RegExp calls and removes raw concatenated booleanRequestTruth', () => {
    const src = readFileSync(resolve(REPO_ROOT, 'src/server/oracle-invariants.ts'), 'utf8')
    assert.equal(/\bnew RegExp\s*\(/.test(src), false, 'oracle-invariants.ts must not invoke new RegExp')
    assert.equal(/\bfunction\s+booleanRequestTruth\b/.test(src), false, 'concatenated raw booleanRequestTruth must be retired')
  })
})
