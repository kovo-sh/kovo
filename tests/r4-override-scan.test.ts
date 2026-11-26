/**
 * R4-H-14 regression & stress guard:
 *  - Eliminates the quadratic `[^\r\n]*\bname` multipart regex DoS in `src/server/scope-policy.ts`.
 *  - Verifies that `classifyRequestMutation`, `detectMethodOverride`, `evaluateScopeRequest`, and
 *    `RequestAdmissionEngine.admit` finish in strictly < 50 ms on 2 MiB adversarial bodies (single-line
 *    repeated `Content-Disposition: form-data; ` prefixes with no `name=` field, multiline headers,
 *    2 MiB form-urlencoded, 2 MiB JSON / malformed JSON) under production Node regex flags.
 *  - Verifies that ALL R3-H-1(b) fail-closed invariants remain intact (bodies > 64 KiB fail closed as
 *    structural / override-risk and reject durable POST route leases; 70 KiB filler + `_method=DELETE`
 *    and nested/malformed multipart payloads are still detected and escalated).
 */
import assert from 'node:assert/strict'
import { performance } from 'node:perf_hooks'
import test from 'node:test'
import {
  classifyRequestMutation,
  isDurableRouteLeaseEligible,
  RequestAdmissionEngine,
} from '../src/server/request-admission.ts'
import type { AdmissionGrant } from '../src/server/request-admission.ts'
import {
  detectMethodOverride,
  evaluateScopeRequest,
  MAX_OVERRIDE_BODY_SCAN_CHARS,
  tenantTagForRun,
} from '../src/server/scope-policy.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'

const APP_ORIGIN = 'https://app.example.test'
const RUN_ID = 'run-r4h14-stress'
const TENANT_TAG = tenantTagForRun(RUN_ID)
const HARD_LATENCY_BUDGET_MS = 50
const TWO_MIB = 2 * 1024 * 1024

function makeScope(overrides: Partial<ScopePolicy> = {}): ScopePolicy {
  return {
    mode: 'staging_isolated',
    targetOrigins: [APP_ORIGIN],
    tenantTag: TENANT_TAG,
    runId: RUN_ID,
    ...overrides,
  }
}

function makeGrant(overrides: Partial<AdmissionGrant> = {}): AdmissionGrant {
  return {
    origin: APP_ORIGIN,
    tier: 3,
    allowLocalLab: false,
    canRead: origin => origin === APP_ORIGIN,
    ...overrides,
  }
}

function measureMs<T>(fn: () => T): { result: T; elapsedMs: number } {
  const start = performance.now()
  const result = fn()
  const elapsedMs = performance.now() - start
  return { result, elapsedMs }
}

// ============================================================================
// 1. 2 MiB adversarial single-line Content-Disposition DoS stress guard (< 50 ms)
// ============================================================================

test('R4-H-14: classifyRequestMutation & detectMethodOverride finish in < 50 ms on 2 MiB single-line repeated Content-Disposition prefixes and fail closed', () => {
  // Exact R4-H-14 quadratic trigger: 2 MiB single line of repeated disposition prefixes, zero newlines, no `name=` field.
  const prefix = 'Content-Disposition: form-data; '
  const adversarial2MiB = prefix.repeat(Math.ceil(TWO_MIB / prefix.length))
  assert.ok(adversarial2MiB.length >= TWO_MIB, `expected >= 2 MiB, got ${adversarial2MiB.length}`)
  assert.equal(adversarial2MiB.includes('\n'), false)

  // Warm JIT on tiny input so measurement reflects steady-state host event loop cost.
  classifyRequestMutation({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/1',
    headers: { 'content-type': 'text/plain' },
    body: 'Content-Disposition: form-data; name="warmup"\r\n\r\nok',
  })

  const contentTypes: Array<{ label: string; headers?: Record<string, string> }> = [
    { label: 'text/plain', headers: { 'content-type': 'text/plain' } },
    { label: 'multipart/form-data', headers: { 'content-type': 'multipart/form-data; boundary=adv2m' } },
    { label: 'no content-type', headers: undefined },
  ]

  for (const tc of contentTypes) {
    const detMeasured = measureMs(() =>
      detectMethodOverride({
        method: 'POST',
        pathAndQuery: '/api/items/42',
        headers: tc.headers,
        body: adversarial2MiB,
      }),
    )
    assert.ok(
      detMeasured.elapsedMs < HARD_LATENCY_BUDGET_MS,
      `detectMethodOverride (${tc.label}) took ${detMeasured.elapsedMs.toFixed(2)} ms (budget ${HARD_LATENCY_BUDGET_MS} ms)`,
    )
    assert.equal(detMeasured.result.bodyExceedsScanWindow, true, tc.label)
    assert.equal(detMeasured.result.hasOverrideRisk, true, tc.label)
    assert.equal(detMeasured.result.hasOverride, false, tc.label)

    const clsMeasured = measureMs(() =>
      classifyRequestMutation({
        origin: APP_ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/items/42',
        headers: tc.headers,
        body: adversarial2MiB,
      }),
    )
    assert.ok(
      clsMeasured.elapsedMs < HARD_LATENCY_BUDGET_MS,
      `classifyRequestMutation (${tc.label}) took ${clsMeasured.elapsedMs.toFixed(2)} ms (budget ${HARD_LATENCY_BUDGET_MS} ms)`,
    )
    assert.equal(clsMeasured.result.hasOverCapBody, true, tc.label)
    assert.equal(clsMeasured.result.hasOverrideRisk, true, tc.label)
    assert.equal(clsMeasured.result.isStructuralMutation, true, tc.label)
    assert.equal(isDurableRouteLeaseEligible(clsMeasured.result), false, tc.label)
  }

  // Also verify end-to-end admission rejects a durable POST route lease in < 50 ms.
  const engine = new RequestAdmissionEngine({ env: {} })
  let leaseCalls = 0
  let approvalCalls = 0
  const admitMeasured = measureMs(() =>
    engine.admit(
      {
        origin: APP_ORIGIN,
        method: 'POST',
        pathAndQuery: `/api/items/42?tenant=${TENANT_TAG}1`,
        headers: { 'content-type': 'text/plain' },
        body: adversarial2MiB,
      },
      makeGrant({
        scopePolicy: makeScope({ mode: 'staging_isolated' }),
        approvalPolicy: 'auto_review',
        approvalLeases: () => {
          leaseCalls += 1
          return true
        },
        isStateChangeApproved: () => {
          approvalCalls += 1
          return false
        },
      }),
    ),
  )
  assert.ok(
    admitMeasured.elapsedMs < HARD_LATENCY_BUDGET_MS,
    `engine.admit took ${admitMeasured.elapsedMs.toFixed(2)} ms (budget ${HARD_LATENCY_BUDGET_MS} ms)`,
  )
  assert.equal(admitMeasured.result.outcome, 'require_approval')
  assert.equal(admitMeasured.result.classification?.isStructuralMutation, true)
  assert.equal(leaseCalls, 0, 'durable POST lease must never authorize >64 KiB adversarial body')
  assert.equal(approvalCalls, 1)

  // And evaluateScopeRequest under prod_readonly refuses in < 50 ms.
  const scopeMeasured = measureMs(() =>
    evaluateScopeRequest(makeScope({ mode: 'prod_readonly' }), {
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items/42',
      headers: { 'content-type': 'text/plain' },
      body: adversarial2MiB,
    }),
  )
  assert.ok(
    scopeMeasured.elapsedMs < HARD_LATENCY_BUDGET_MS,
    `evaluateScopeRequest took ${scopeMeasured.elapsedMs.toFixed(2)} ms (budget ${HARD_LATENCY_BUDGET_MS} ms)`,
  )
  assert.equal(scopeMeasured.result.allowed, false)
  assert.equal(scopeMeasured.result.code, 'readonly_environment')
})

// ============================================================================
// 2. Additional 2 MiB adversarial variants (override at tail, multiline, form, JSON)
// ============================================================================

test('R4-H-14: 2 MiB adversarial variants (tail _method, multiline headers, 500k form pairs, 2 MiB JSON / malformed JSON) all finish in < 50 ms and fail closed', () => {
  const prefix = 'Content-Disposition: form-data; '
  const repeatCount = Math.ceil(TWO_MIB / prefix.length)

  // 2a. 2 MiB single-line disposition prefix WITH real `name="_method"\r\n\r\nDELETE` at the tail.
  const tailOverride2MiB = `${prefix.repeat(repeatCount)}name="_method"\r\n\r\nDELETE\r\n--end--\r\n`
  const tailMeasured = measureMs(() =>
    classifyRequestMutation({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items/42',
      headers: { 'content-type': 'multipart/form-data; boundary=end' },
      body: tailOverride2MiB,
    }),
  )
  assert.ok(
    tailMeasured.elapsedMs < HARD_LATENCY_BUDGET_MS,
    `2 MiB tail-override multipart took ${tailMeasured.elapsedMs.toFixed(2)} ms`,
  )
  assert.equal(tailMeasured.result.hasMethodOverride, true)
  assert.equal(tailMeasured.result.effectiveMethod, 'DELETE')
  assert.equal(tailMeasured.result.hasOverCapBody, true)
  assert.equal(tailMeasured.result.isStructuralMutation, true)
  assert.equal(isDurableRouteLeaseEligible(tailMeasured.result), false)

  // 2b. 2 MiB multiline repeated `Content-Disposition: form-data; name="file"\r\n`
  const line = 'Content-Disposition: form-data; name="file"\r\n'
  const multiline2MiB = line.repeat(Math.ceil(TWO_MIB / line.length))
  const multiMeasured = measureMs(() =>
    classifyRequestMutation({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items/42',
      headers: { 'content-type': 'text/plain' },
      body: multiline2MiB,
    }),
  )
  assert.ok(
    multiMeasured.elapsedMs < HARD_LATENCY_BUDGET_MS,
    `2 MiB multiline headers took ${multiMeasured.elapsedMs.toFixed(2)} ms`,
  )
  assert.equal(multiMeasured.result.hasOverCapBody, true)
  assert.equal(multiMeasured.result.hasOverrideRisk, true)
  assert.equal(multiMeasured.result.isStructuralMutation, true)
  assert.equal(isDurableRouteLeaseEligible(multiMeasured.result), false)

  // 2c. 2 MiB single-line repeated `name="other"; ` parameters
  const nameRepeat = 'name="other"; '
  const repeatedNames2MiB = `${prefix}${nameRepeat.repeat(Math.ceil(TWO_MIB / nameRepeat.length))}`
  const namesMeasured = measureMs(() =>
    classifyRequestMutation({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items/42',
      headers: { 'content-type': 'text/plain' },
      body: repeatedNames2MiB,
    }),
  )
  assert.ok(
    namesMeasured.elapsedMs < HARD_LATENCY_BUDGET_MS,
    `2 MiB repeated name params took ${namesMeasured.elapsedMs.toFixed(2)} ms`,
  )
  assert.equal(namesMeasured.result.isStructuralMutation, true)
  assert.equal(isDurableRouteLeaseEligible(namesMeasured.result), false)

  // 2d. 2 MiB form-urlencoded with 524k key=value pairs (`a=1&a=1&...`)
  const formPair = 'a=1&'
  const hugeForm2MiB = formPair.repeat(Math.ceil(TWO_MIB / formPair.length))
  const formMeasured = measureMs(() =>
    classifyRequestMutation({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items/42',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: hugeForm2MiB,
    }),
  )
  assert.ok(
    formMeasured.elapsedMs < HARD_LATENCY_BUDGET_MS,
    `2 MiB 524k-pair form took ${formMeasured.elapsedMs.toFixed(2)} ms`,
  )
  assert.equal(formMeasured.result.hasOverCapBody, true)
  assert.equal(formMeasured.result.hasOverrideRisk, true)
  assert.equal(formMeasured.result.isStructuralMutation, true)
  assert.equal(isDurableRouteLeaseEligible(formMeasured.result), false)

  // 2e. 2 MiB adversarial malformed JSON (`{"_method"    ` repeated) directly against detectMethodOverride
  const badJsonChunk = '{"_method"    '
  const badJson2MiB = badJsonChunk.repeat(Math.ceil(TWO_MIB / badJsonChunk.length))
  const badJsonMeasured = measureMs(() =>
    detectMethodOverride({
      method: 'POST',
      pathAndQuery: '/api/items/42',
      headers: { 'content-type': 'application/json' },
      body: badJson2MiB,
    }),
  )
  assert.ok(
    badJsonMeasured.elapsedMs < HARD_LATENCY_BUDGET_MS,
    `2 MiB malformed JSON detectMethodOverride took ${badJsonMeasured.elapsedMs.toFixed(2)} ms`,
  )
  assert.equal(badJsonMeasured.result.bodyExceedsScanWindow, true)
  assert.equal(badJsonMeasured.result.scanIncomplete, true)
  assert.equal(badJsonMeasured.result.hasOverrideRisk, true)

  // 2f. 2 MiB JSON with ~350k properties directly against detectMethodOverride
  const jsonProp = '"b":2,'
  const manyPropsJson2MiB = `{"a":1,${jsonProp.repeat(Math.ceil(TWO_MIB / jsonProp.length))}"_method":"DELETE"}`
  const manyPropsMeasured = measureMs(() =>
    detectMethodOverride({
      method: 'POST',
      pathAndQuery: '/api/items/42',
      headers: { 'content-type': 'application/json' },
      body: manyPropsJson2MiB,
    }),
  )
  assert.ok(
    manyPropsMeasured.elapsedMs < HARD_LATENCY_BUDGET_MS,
    `2 MiB 350k-key JSON detectMethodOverride took ${manyPropsMeasured.elapsedMs.toFixed(2)} ms`,
  )
  assert.equal(manyPropsMeasured.result.bodyExceedsScanWindow, true)
  assert.equal(manyPropsMeasured.result.hasOverride, true)
  assert.equal(manyPropsMeasured.result.effectiveMethod, 'DELETE')
  assert.ok(manyPropsMeasured.result.carriers.includes('json:_method'))
})

// ============================================================================
// 3. Nested/malformed multipart & 70 KiB filler + _method=DELETE fail-closed parity
// ============================================================================

test('R4-H-14: nested/malformed multipart and 70 KiB filler + _method=DELETE payloads are detected and fail closed in < 50 ms', () => {
  const filler70k = 'x'.repeat(70 * 1024)
  assert.ok(filler70k.length > MAX_OVERRIDE_BODY_SCAN_CHARS)

  const cases: Array<{
    label: string
    headers: Record<string, string>
    body: string
    expectedMethod: string
    expectedCarrier?: string
    expectScanIncomplete?: boolean
  }> = [
    {
      label: '70 KiB filler + form _method=DELETE',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `pad=${filler70k}&_method=DELETE`,
      expectedMethod: 'DELETE',
      expectedCarrier: 'form:_method',
    },
    {
      label: '70 KiB filler + JSON _method=DELETE',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pad: filler70k, _method: 'DELETE' }),
      expectedMethod: 'DELETE',
      expectedCarrier: 'json:_method',
    },
    {
      label: '70 KiB filler + multipart _method=DELETE',
      headers: { 'content-type': 'multipart/form-data; boundary=kovo70k' },
      body:
        `--kovo70k\r\nContent-Disposition: form-data; name="pad"\r\n\r\n${filler70k}\r\n` +
        `--kovo70k\r\nContent-Disposition: form-data; name="_method"\r\n\r\nDELETE\r\n--kovo70k--\r\n`,
      expectedMethod: 'DELETE',
      expectedCarrier: 'multipart:_method',
    },
    {
      label: 'nested multipart with extra Content-Type header before blank line',
      headers: { 'content-type': 'multipart/mixed; boundary=outer' },
      body:
        `--outer\r\nContent-Type: multipart/form-data; boundary=inner\r\n\r\n` +
        `--inner\r\nContent-Disposition: form-data; filename="a;b"; name="_method"\r\n` +
        `Content-Type: text/plain; charset=utf-8\r\n\r\nDELETE\r\n--inner--\r\n--outer--\r\n`,
      expectedMethod: 'DELETE',
      expectedCarrier: 'multipart:_method',
    },
    {
      label: 'folded RFC 5322 Content-Disposition continuation line',
      headers: { 'content-type': 'multipart/form-data; boundary=fold' },
      body:
        `--fold\r\nContent-Disposition: form-data;\r\n name="_method"\r\n\r\nPUT\r\n--fold--\r\n`,
      expectedMethod: 'PUT',
      expectedCarrier: 'multipart:_method',
    },
    {
      label: 'malformed multipart missing boundary & truncated without blank line',
      headers: { 'content-type': 'multipart/form-data' },
      body: `--broken\r\nContent-Disposition: form-data; name=_method`,
      expectedMethod: 'POST',
      expectedCarrier: 'multipart:_method',
      expectScanIncomplete: true,
    },
  ]

  for (const tc of cases) {
    const measured = measureMs(() =>
      classifyRequestMutation({
        origin: APP_ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/items/42',
        headers: tc.headers,
        body: tc.body,
      }),
    )
    assert.ok(
      measured.elapsedMs < HARD_LATENCY_BUDGET_MS,
      `${tc.label} took ${measured.elapsedMs.toFixed(2)} ms`,
    )
    assert.equal(measured.result.isStructuralMutation, true, tc.label)
    assert.equal(measured.result.hasOverrideRisk, true, tc.label)
    assert.equal(measured.result.effectiveMethod, tc.expectedMethod, tc.label)
    assert.equal(isDurableRouteLeaseEligible(measured.result), false, tc.label)
    if (tc.expectedCarrier) {
      assert.equal(measured.result.hasMethodOverride, true, tc.label)
      assert.ok(
        measured.result.methodOverrideCarriers?.includes(tc.expectedCarrier),
        `${tc.label}: expected carrier ${tc.expectedCarrier}, got ${JSON.stringify(measured.result.methodOverrideCarriers)}`,
      )
    }
    if (tc.expectScanIncomplete) {
      assert.equal(measured.result.overrideScanIncomplete, true, tc.label)
    }
  }
})
