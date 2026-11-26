// @kernel @fixes R3-H-1
/**
 * R3-H-1(a) & R3-H-1(b) regression suite:
 *  - R3-H-1(a): Derived (non-explicit) `staging_isolated` under `auto_review` MUST NOT
 *    auto-approve state-changing writes via host-injected `stagingProbeTag` /
 *    `tagStagingEntityBody` body fields or any tenant tag; every non-read-only write without an
 *    eligible durable operator lease MUST invoke `isStateChangeApproved` (`require_approval`).
 *  - R3-H-1(b): `detectMethodOverride` NEVER truncates at 64 KiB; form, JSON, and multipart
 *    bodies with `_method` after 70 KiB of filler (as well as plain over-cap >64 KiB and
 *    unscannable bodies) are classified structural / override-risk everywhere, escalate to
 *    approval, and NEVER satisfy a durable POST route lease (`checkLease`) under ANY policy.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import type { ApprovalPolicy } from '../src/domain.ts'
import { authorizeStateChange, evaluateTier3Approval } from '../src/server/approval-judge.ts'
import { stagingProbeTag, tagStagingEntityBody, tagStagingEntityForm } from '../src/server/deterministic-engine.ts'
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
  requestCarriesTenantTag,
  tenantTagForRun,
} from '../src/server/scope-policy.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'

const APP_ORIGIN = 'https://app.example.test'
const RUN_ID = 'run-r3h1-verify'
const TENANT_TAG = tenantTagForRun(RUN_ID)

function makeScope(overrides: Partial<ScopePolicy> = {}): ScopePolicy {
  return {
    mode: 'staging_isolated',
    targetOrigins: [APP_ORIGIN],
    routeDenylist: ['/billing/charge'],
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

// ============================================================================
// 1. R3-H-1(a): Derived staging_isolated + auto_review never auto-approves
//    writes via host-injected stagingProbeTag / tagStagingEntityBody tags
// ============================================================================

test('R3-H-1(a): derived staging_isolated + auto_review routes stagingProbeTag-built PATCH/PUT through isStateChangeApproved', () => {
  const engine = new RequestAdmissionEngine({ env: {} })
  const scope = makeScope({ mode: 'staging_isolated' })

  for (const method of ['PATCH', 'PUT', 'POST'] as const) {
    const tagged = stagingProbeTag({
      environmentMode: 'staging_isolated',
      entityTag: TENANT_TAG,
      runId: RUN_ID,
      method,
      probeClass: 'mass_assignment',
      pathAndQuery: '/api/users/42',
      jsonBody: { role: 'admin', is_admin: true, name: 'alice' },
    })
    assert.equal(tagged.action, 'tag')
    assert.equal(tagged.jsonBody?.name, `${TENANT_TAG}alice`)

    const body = JSON.stringify(tagged.jsonBody)
    const headers = { ...(tagged.headers ?? {}), 'content-type': 'application/json' }

    // Host-injected headers + host-taggable entity body field (`name`) MUST NOT satisfy
    // tenant isolation proof on derived staging runs.
    assert.equal(
      requestCarriesTenantTag(
        { origin: APP_ORIGIN, method, pathAndQuery: '/api/users/42', headers, body },
        TENANT_TAG,
        { ignoreHostInjectedHeaders: true },
      ),
      false,
      `${method}: host-tagged name field must not satisfy requestCarriesTenantTag`,
    )
    const derivedScopeDecision = evaluateScopeRequest(
      { ...scope, derivedEnvironmentMode: true },
      { origin: APP_ORIGIN, method, pathAndQuery: '/api/users/42', headers, body },
    )
    assert.equal(derivedScopeDecision.allowed, false, `${method}: derived scope must reject host-only body tag`)
    assert.equal(derivedScopeDecision.code, 'staging_untagged_mutation')

    // Admission on derived staging_isolated + auto_review MUST call isStateChangeApproved
    // and return require_approval (0 silent auto-approvals).
    let hookCalls = 0
    const derivedGrant = makeGrant({
      scopePolicy: scope,
      approvalPolicy: 'auto_review',
      isStateChangeApproved: () => {
        hookCalls += 1
        return false
      },
    })
    const decision = engine.admit(
      { origin: APP_ORIGIN, method, pathAndQuery: '/api/users/42', headers, body },
      derivedGrant,
    )
    assert.equal(decision.outcome, 'require_approval', `${method}: must require approval on derived staging`)
    assert.equal(decision.reasonCode, 'approval_required')
    assert.equal(hookCalls, 1, `${method}: isStateChangeApproved must be invoked exactly once`)
  }
})

test('R3-H-1(a): derived staging_isolated + auto_review drops ALL tag-based auto-approve bypasses (path, body, form, hook) while preserving read-only & explicit staging', () => {
  const engine = new RequestAdmissionEngine({ env: {} })
  const scope = makeScope({ mode: 'staging_isolated' })

  const formBody = new URLSearchParams(
    tagStagingEntityForm({ role: 'admin', name: 'alice' }, TENANT_TAG),
  ).toString()

  const derivedWriteCases = [
    {
      label: 'path query tenant tag',
      req: {
        origin: APP_ORIGIN,
        method: 'PATCH',
        pathAndQuery: `/api/users/42?tenant=${TENANT_TAG}1`,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ role: 'admin' }),
      },
    },
    {
      label: 'non-entity JSON tenant field',
      req: {
        origin: APP_ORIGIN,
        method: 'PUT',
        pathAndQuery: '/api/users/42',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tenant: `${TENANT_TAG}1`, role: 'admin' }),
      },
    },
    {
      label: 'form body tagged by tagStagingEntityForm',
      req: {
        origin: APP_ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/users/42',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: formBody,
      },
    },
    {
      label: 'setup hook on derived staging',
      req: {
        origin: APP_ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/users/42',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ role: 'admin' }),
        scopeHook: 'setup' as const,
      },
    },
  ]

  for (const tc of derivedWriteCases) {
    let hookCalls = 0
    const grant = makeGrant({
      scopePolicy: scope,
      approvalPolicy: 'auto_review',
      isStateChangeApproved: () => {
        hookCalls += 1
        return false
      },
    })
    const decision = engine.admit(tc.req, grant)
    assert.equal(decision.outcome, 'require_approval', `${tc.label}: must escalate on derived staging`)
    assert.equal(hookCalls, 1, `${tc.label}: must consult isStateChangeApproved`)
  }

  // Read-only GET on derived staging_isolated + auto_review still passes without approval prompts.
  let readHookCalls = 0
  const readDecision = engine.admit(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/users/42' },
    makeGrant({
      scopePolicy: scope,
      approvalPolicy: 'auto_review',
      isStateChangeApproved: () => {
        readHookCalls += 1
        return false
      },
    }),
  )
  assert.equal(readDecision.outcome, 'allow')
  assert.equal(readDecision.reasonCode, 'allowed_read_only')
  assert.equal(readHookCalls, 0)

  // Explicit operator-declared staging_isolated (approvalPolicy omitted -> explicitEnvironmentMode=true)
  // retains its contract behavior for honest tagged non-override writes.
  const taggedBody = JSON.stringify(tagStagingEntityBody({ name: 'synthetic-item' }, TENANT_TAG))
  let explicitHookCalls = 0
  const explicitDecision = engine.admit(
    {
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items',
      headers: {
        'content-type': 'application/json',
        'x-kovo-tenant-tag': TENANT_TAG,
        'x-kovo-run-id': RUN_ID,
      },
      body: taggedBody,
    },
    makeGrant({
      scopePolicy: scope,
      approvalPolicy: undefined,
      isStateChangeApproved: () => {
        explicitHookCalls += 1
        return false
      },
    }),
  )
  assert.equal(explicitDecision.outcome, 'allow')
  assert.equal(explicitDecision.reasonCode, 'allowed_environment_contract')
  assert.equal(explicitHookCalls, 0)
})

// ============================================================================
// 2. R3-H-1(b): Method override after 70 KiB filler (form, JSON, multipart)
//    and plain over-cap / malformed bodies MUST be structural and fail checkLease
// ============================================================================

test('R3-H-1(b): form & JSON _method=DELETE placed after 70 KiB filler are detected, classified structural, escalate to approval, and fail durable POST leases under ANY policy', async () => {
  const filler = 'a'.repeat(70 * 1024)
  assert.ok(filler.length > MAX_OVERRIDE_BODY_SCAN_CHARS)

  const overridePayloads = [
    {
      label: 'form-urlencoded _method=DELETE after 70 KiB filler',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `pad=${filler}&_method=DELETE`,
      expectedCarrier: 'form:_method',
    },
    {
      label: 'JSON _method=DELETE after 70 KiB filler',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pad: filler, _method: 'DELETE', name: `${TENANT_TAG}item` }),
      expectedCarrier: 'json:_method',
    },
    {
      label: 'multipart _method=DELETE after 70 KiB filler',
      headers: { 'content-type': 'multipart/form-data; boundary=kovo70k' },
      body:
        `--kovo70k\r\nContent-Disposition: form-data; name="pad"\r\n\r\n${filler}\r\n` +
        `--kovo70k\r\nContent-Disposition: form-data; name="_method"\r\n\r\nDELETE\r\n--kovo70k--\r\n`,
      expectedCarrier: 'multipart:_method',
    },
  ]

  const engine = new RequestAdmissionEngine({ env: {} })
  const policies: Array<ApprovalPolicy | undefined> = ['auto_review', 'strict', 'yolo', undefined]
  const postPattern = [{ origin: APP_ORIGIN, method: 'POST', pathPattern: '/api/items/*' }]

  for (const tc of overridePayloads) {
    // 1. detectMethodOverride must NOT truncate at 64 KiB
    const det = detectMethodOverride({
      method: 'POST',
      pathAndQuery: `/api/items/42?tenant=${TENANT_TAG}1`,
      headers: tc.headers,
      body: tc.body,
    })
    assert.equal(det.hasOverride, true, tc.label)
    assert.equal(det.bodyExceedsScanWindow, true, tc.label)
    assert.equal(det.hasOverrideRisk, true, tc.label)
    assert.equal(det.effectiveMethod, 'DELETE', tc.label)
    assert.ok(det.carriers.includes(tc.expectedCarrier), `${tc.label}: got ${det.carriers.join(',')}`)

    // 2. classifyRequestMutation + shared isDurableRouteLeaseEligible helper
    const cls = classifyRequestMutation({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: `/api/items/42?tenant=${TENANT_TAG}1`,
      headers: tc.headers,
      body: tc.body,
    })
    assert.equal(cls.hasMethodOverride, true, tc.label)
    assert.equal(cls.hasOverCapBody, true, tc.label)
    assert.equal(cls.hasOverrideRisk, true, tc.label)
    assert.equal(cls.isStructuralMutation, true, tc.label)
    assert.equal(cls.effectiveMethod, 'DELETE', tc.label)
    assert.equal(isDurableRouteLeaseEligible(cls), false, tc.label)

    // 3. Derived staging_isolated (`auto_review` and `strict`) AND explicit staging_isolated:
    //    MUST return require_approval even WITH a path tenant tag AND a durable POST route lease.
    for (const approvalPolicy of ['auto_review', 'strict', undefined] as Array<ApprovalPolicy | undefined>) {
      let leaseCalls = 0
      let approvalCalls = 0
      const decision = engine.admit(
        {
          origin: APP_ORIGIN,
          method: 'POST',
          pathAndQuery: `/api/items/42?tenant=${TENANT_TAG}1`,
          headers: tc.headers,
          body: tc.body,
        },
        makeGrant({
          scopePolicy: makeScope({ mode: 'staging_isolated' }),
          approvalPolicy,
          approvalLeases: () => {
            leaseCalls += 1
            return true
          },
          isStateChangeApproved: () => {
            approvalCalls += 1
            return false
          },
        }),
      )
      assert.equal(decision.outcome, 'require_approval', `${tc.label} staging policy=${String(approvalPolicy)}`)
      assert.equal(decision.classification?.isStructuralMutation, true)
      assert.equal(leaseCalls, 0, `${tc.label} policy=${String(approvalPolicy)}: durable POST lease must never be authorized`)
      assert.equal(approvalCalls, 1, `${tc.label} policy=${String(approvalPolicy)}: must invoke isStateChangeApproved`)
    }

    // 4. Durable POST route lease under prod_readonly AND ephemeral_lab MUST fail under ANY policy
    //    (auto_review, strict, yolo, explicit).
    for (const approvalPolicy of policies) {
      let prodLeaseCalls = 0
      const prodDecision = engine.admit(
        {
          origin: APP_ORIGIN,
          method: 'POST',
          pathAndQuery: '/api/items/42',
          headers: tc.headers,
          body: tc.body,
        },
        makeGrant({
          scopePolicy: makeScope({ mode: 'prod_readonly' }),
          approvalPolicy,
          approvalLeases: (o, m, p) => {
            prodLeaseCalls += 1
            return o === APP_ORIGIN && m === 'POST' && p.startsWith('/api/items/')
          },
          isStateChangeApproved: () => false,
        }),
      )
      assert.equal(prodDecision.allowed, false, `${tc.label} prod_readonly policy=${String(approvalPolicy)}`)
      assert.equal(prodDecision.reasonCode, 'readonly_environment')
      assert.equal(prodLeaseCalls, 0, `${tc.label} prod_readonly policy=${String(approvalPolicy)}: lease must not be consumed`)

      let labLeaseCalls = 0
      let labApprovalCalls = 0
      const labDecision = engine.admit(
        {
          origin: APP_ORIGIN,
          method: 'POST',
          pathAndQuery: '/api/items/42',
          headers: tc.headers,
          body: tc.body,
        },
        makeGrant({
          scopePolicy: makeScope({ mode: 'ephemeral_lab' }),
          approvalPolicy,
          approvalLeases: () => {
            labLeaseCalls += 1
            return true
          },
          isStateChangeApproved: () => {
            labApprovalCalls += 1
            return false
          },
        }),
      )
      assert.equal(labDecision.outcome, 'require_approval', `${tc.label} ephemeral_lab policy=${String(approvalPolicy)}`)
      assert.equal(labLeaseCalls, 0, `${tc.label} ephemeral_lab policy=${String(approvalPolicy)}: lease must not authorize`)
      assert.equal(labApprovalCalls, 1)
    }

    // 5. Safety judge (`evaluateTier3Approval`) and `authorizeStateChange` agree with admission.
    const judgePatternVerdict = await evaluateTier3Approval({
      policy: 'auto_review',
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items/42',
      headers: tc.headers,
      bodyPreview: tc.body,
      approvedPatterns: postPattern,
      offline: true,
    })
    assert.equal(judgePatternVerdict.decision, 'escalate_human', `${tc.label}: judge must escalate`)
    assert.equal(judgePatternVerdict.stage, 'hard_escalation', tc.label)

    const judgeStagingVerdict = await evaluateTier3Approval({
      policy: 'auto_review',
      mode: 'staging_isolated',
      tenantTag: TENANT_TAG,
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: `/api/items/42?tenant=${TENANT_TAG}1`,
      headers: tc.headers,
      bodyPreview: tc.body,
      offline: true,
    })
    assert.equal(judgeStagingVerdict.decision, 'escalate_human', `${tc.label}: judge staging must escalate`)
    assert.equal(judgeStagingVerdict.stage, 'hard_escalation', tc.label)

    const authVerdict = authorizeStateChange({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items/42',
      context: {
        headers: tc.headers,
        body: tc.body,
        hasMethodOverride: cls.hasMethodOverride,
      },
      approvedPatterns: postPattern,
    })
    assert.equal(authVerdict.approved, false, `${tc.label}: operator POST pattern must not authorize`)
  }
})

test('R3-H-1(b): plain over-cap (>64 KiB), malformed JSON, and >4 MiB unscannable bodies fail closed as structural & reject durable leases', () => {
  const engine = new RequestAdmissionEngine({ env: {} })
  const plainOverCapJson = JSON.stringify({ pad: 'b'.repeat(70 * 1024), name: `${TENANT_TAG}item` })
  const malformedJson = '{"pad":"unterminated'
  const overHardCapBody = 'x'.repeat(4 * 1024 * 1024 + 128)

  // 1. Plain >64 KiB JSON (no _method): structural + over-cap + fails durable POST lease + escalates
  const overCapCls = classifyRequestMutation({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/42',
    headers: { 'content-type': 'application/json' },
    body: plainOverCapJson,
  })
  assert.equal(overCapCls.hasMethodOverride, false)
  assert.equal(overCapCls.hasOverCapBody, true)
  assert.equal(overCapCls.hasOverrideRisk, true)
  assert.equal(overCapCls.isStructuralMutation, true)
  assert.equal(isDurableRouteLeaseEligible(overCapCls), false)

  let overCapLeaseCalls = 0
  const overCapProd = engine.admit(
    {
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items/42',
      headers: { 'content-type': 'application/json' },
      body: plainOverCapJson,
    },
    makeGrant({
      scopePolicy: makeScope({ mode: 'prod_readonly' }),
      approvalPolicy: 'auto_review',
      approvalLeases: () => {
        overCapLeaseCalls += 1
        return true
      },
    }),
  )
  assert.equal(overCapProd.allowed, false)
  assert.equal(overCapProd.reasonCode, 'readonly_environment')
  assert.equal(overCapLeaseCalls, 0)

  const overCapExplicitStaging = engine.admit(
    {
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: `/api/items/42?tenant=${TENANT_TAG}1`,
      headers: { 'content-type': 'application/json' },
      body: plainOverCapJson,
    },
    makeGrant({
      scopePolicy: makeScope({ mode: 'staging_isolated' }),
      approvalPolicy: undefined,
      isStateChangeApproved: () => false,
    }),
  )
  assert.equal(overCapExplicitStaging.outcome, 'require_approval')

  // 2. Malformed JSON (unscannable): structural + overrideScanIncomplete + fails durable POST lease
  const malformedCls = classifyRequestMutation({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/42',
    headers: { 'content-type': 'application/json' },
    body: malformedJson,
  })
  assert.equal(malformedCls.overrideScanIncomplete, true)
  assert.equal(malformedCls.hasOverrideRisk, true)
  assert.equal(malformedCls.isStructuralMutation, true)
  assert.equal(isDurableRouteLeaseEligible(malformedCls), false)

  // 3. Body exceeding 4 MiB full-scan ceiling: fails closed with explicit scan-cap carrier
  const hugeDet = detectMethodOverride({
    method: 'POST',
    pathAndQuery: '/api/items/42',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: overHardCapBody,
  })
  assert.equal(hugeDet.hasOverride, true)
  assert.equal(hugeDet.bodyExceedsScanWindow, true)
  assert.equal(hugeDet.scanIncomplete, true)
  assert.equal(hugeDet.hasOverrideRisk, true)
  assert.ok(hugeDet.carriers.includes('body:exceeds_scan_cap'))
})
