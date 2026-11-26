import assert from 'node:assert/strict'
import test from 'node:test'
import {
  computeHostApprovalRiskFloor,
  evaluateTier3Approval,
} from '../src/server/approval-judge.ts'
import type { ApprovalDecisionKind, ApprovalRiskLevel } from '../src/server/approval-judge.ts'
import { BrokerCircuitOpen, RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  classifyRequestMutation,
  RequestAdmissionEngine,
  resolveGrantApprovalContext,
} from '../src/server/request-admission.ts'
import type { AdmissionGrant } from '../src/server/request-admission.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'
import { tenantTagForRun } from '../src/server/scope-policy.ts'

const APP_ORIGIN = 'https://app.r2-01.example'
const PUBLIC_ADDR = { address: '93.184.216.34', family: 4 as const }

function makeBrokerGrant(origin: string): Grant {
  return {
    origin,
    tier: 2,
    allowLocalLab: false,
    canRead: candidate => candidate === origin,
    isStateChangeApproved: () => false,
    audit: () => {},
  }
}

// ============================================================================
// 1. Judge fail-closed matrix: decision x riskLevel (incl. missing/invalid) x hostFloor
// ============================================================================

test('R2-01 Judge matrix: auto_review NEVER approves when hostFloor > low or riskLevel is missing/invalid', async () => {
  const decisions: ApprovalDecisionKind[] = ['approve', 'escalate_human', 'deny']
  const rawRiskLevels: Array<{ label: string; value: unknown; isExplicitValid: boolean; expectedJudgeRisk: ApprovalRiskLevel }> = [
    { label: 'low', value: 'low', isExplicitValid: true, expectedJudgeRisk: 'low' },
    { label: 'medium', value: 'medium', isExplicitValid: true, expectedJudgeRisk: 'medium' },
    { label: 'high', value: 'high', isExplicitValid: true, expectedJudgeRisk: 'high' },
    { label: 'missing', value: undefined, isExplicitValid: false, expectedJudgeRisk: 'high' },
    { label: 'invalid-string', value: 'critical', isExplicitValid: false, expectedJudgeRisk: 'high' },
    { label: 'invalid-number', value: 1, isExplicitValid: false, expectedJudgeRisk: 'high' },
  ]
  const hostFloors: ApprovalRiskLevel[] = ['low', 'medium', 'high']
  const riskRank: Record<ApprovalRiskLevel, number> = { low: 0, medium: 1, high: 2 }

  for (const decision of decisions) {
    for (const rl of rawRiskLevels) {
      for (const hostFloor of hostFloors) {
        const label = `decision=${decision} riskLevel=${rl.label} hostFloor=${hostFloor}`
        const payload: Record<string, unknown> = {
          decision,
          reason: `Matrix probe (${label}).`,
        }
        if (rl.value !== undefined) {
          payload.riskLevel = rl.value
        }

        const res = await evaluateTier3Approval({
          policy: 'auto_review',
          origin: APP_ORIGIN,
          method: 'POST',
          pathAndQuery: '/api/comments',
          personaHandle: 'user_a',
          bodyPreview: '{"text":"benign"}',
          hostFloor,
          offline: false,
          llmCall: async () => JSON.stringify(payload),
        })

        const expectedEffectiveRisk: ApprovalRiskLevel =
          riskRank[hostFloor] >= riskRank[rl.expectedJudgeRisk] ? hostFloor : rl.expectedJudgeRisk

        // Audit fields ALWAYS reflect the raw Judge verdict & host floor.
        assert.equal(res.originalJudgeDecision, decision, `${label}: originalJudgeDecision`)
        assert.equal(
          res.originalRiskLevel,
          rl.isExplicitValid ? (rl.value as ApprovalRiskLevel) : null,
          `${label}: originalRiskLevel`,
        )
        assert.equal(res.hostFloor, hostFloor, `${label}: hostFloor`)
        assert.equal(res.riskLevel, expectedEffectiveRisk, `${label}: effective risk = max(hostFloor, judgeRisk)`)

        // Hard invariants:
        if (hostFloor !== 'low') {
          assert.notEqual(res.decision, 'approve', `${label}: NEVER approve when hostFloor > low`)
        }
        if (!rl.isExplicitValid) {
          assert.notEqual(res.decision, 'approve', `${label}: NEVER approve when riskLevel is missing/invalid`)
          assert.equal(res.riskLevel, 'high', `${label}: missing/invalid riskLevel MUST escalate to high`)
        }

        if (decision === 'deny') {
          assert.equal(res.decision, 'deny', `${label}: deny must be preserved`)
          assert.equal(res.decidedBy, 'auto-review:judge', `${label}: deny attributed to judge`)
        } else if (hostFloor === 'low' && rl.isExplicitValid && (rl.value === 'low' || rl.value === 'medium')) {
          assert.equal(res.decision, 'approve', `${label}: low hostFloor + explicit low/medium approves`)
          assert.equal(
            res.decidedBy,
            decision === 'escalate_human' ? 'auto-review:policy' : 'auto-review:judge',
            `${label}: Stage-2 escalation normalization must credit auto-review:policy, not judge`,
          )
        } else {
          assert.equal(res.decision, 'escalate_human', `${label}: must fail closed to escalate_human`)
          assert.equal(res.decidedBy, 'operator', `${label}: escalated decision owned by operator`)
        }
      }
    }
  }
})

test('R2-01 hostFloor derivation: classifyRequestMutation signals & domain HIGH_RISK tokens lift floor to high/medium', async () => {
  // 1. jsonrpc_destructive -> hostFloor 'high' (even when Judge returns approve + low)
  const jsonRpcBody = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'users.deleteAll', params: {} })
  const rpcClass = classifyRequestMutation({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/rpc',
    headers: { 'content-type': 'application/json' },
    body: jsonRpcBody,
  })
  assert.equal(rpcClass.kind, 'jsonrpc_destructive')
  assert.equal(rpcClass.isStructuralMutation, true)
  assert.equal(
    computeHostApprovalRiskFloor({
      method: 'POST',
      pathAndQuery: '/rpc',
      headers: { 'content-type': 'application/json' },
      bodyPreview: jsonRpcBody,
      isStructuralMutation: rpcClass.isStructuralMutation,
      mutationKind: rpcClass.kind,
    }),
    'high',
  )

  const rpcVerdict = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/rpc',
    headers: { 'content-type': 'application/json' },
    bodyPreview: jsonRpcBody,
    personaHandle: 'user_a',
    offline: false,
    llmCall: async () => JSON.stringify({ decision: 'approve', riskLevel: 'low', reason: 'Looks benign' }),
  })
  assert.equal(rpcVerdict.decision, 'escalate_human')
  assert.equal(rpcVerdict.riskLevel, 'high')
  assert.equal(rpcVerdict.hostFloor, 'high')
  assert.equal(rpcVerdict.originalJudgeDecision, 'approve')
  assert.equal(rpcVerdict.originalRiskLevel, 'low')

  // 2. RequestAdmissionEngine computes hostFloor from classifyRequestMutation & attaches it to approvalContext
  const engine = new RequestAdmissionEngine({ env: {} })
  let seenHostFloor: ApprovalRiskLevel | undefined
  const grant: AdmissionGrant = {
    origin: APP_ORIGIN,
    tier: 3,
    allowLocalLab: false,
    approvalPolicy: 'auto_review',
    canRead: o => o === APP_ORIGIN,
    isStateChangeApproved: (_origin, _method, _path, ctx) => {
      seenHostFloor = ctx?.hostFloor
      return false
    },
  }
  const decision = engine.admit(
    {
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/rpc',
      headers: { 'content-type': 'application/json' },
      body: jsonRpcBody,
      personaHandle: 'user_a',
    },
    grant,
  )
  assert.equal(decision.outcome, 'require_approval')
  assert.equal(seenHostFloor, 'high')
  assert.equal(decision.approvalContext?.hostFloor, 'high')

  // 3. Domain HIGH_RISK_PATH_TOKENS (e.g. /api/admin/settings, /api/billing/plan, /api/emails) -> hostFloor 'high'
  for (const path of ['/api/admin/settings', '/api/billing/plan', '/api/emails', '/api/password/reset']) {
    const res = await evaluateTier3Approval({
      policy: 'auto_review',
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: path,
      personaHandle: null,
      bodyPreview: '{"x":1}',
      offline: false,
      llmCall: async () => JSON.stringify({ decision: 'escalate_human', riskLevel: 'low', reason: 'Unauth probe' }),
    })
    assert.equal(res.decision, 'escalate_human', `${path} must escalate under domain HIGH_RISK floor`)
    assert.equal(res.hostFloor, 'high', `${path} must derive hostFloor='high'`)
    assert.equal(res.riskLevel, 'high')
  }
})

// ============================================================================
// 2. Broker 5xx breaker exemption: origin-down 502/52x NEVER exempt; bounded plain 500/501 caps route breaker
// ============================================================================

test('R2-01 broker breaker: 502 and 52x bursts under ANY probeClass open the origin breaker', async () => {
  const originDownCases: Array<{ status: number; probeClass: string }> = [
    { status: 502, probeClass: 'sqli_boolean' },
    { status: 503, probeClass: 'ssti_math' },
    { status: 504, probeClass: 'xxe_canary' },
    { status: 520, probeClass: 'nosql_injection' },
    { status: 522, probeClass: 'xpath_injection' },
    { status: 525, probeClass: 'deserial_probe' },
    { status: 526, probeClass: 'template_expression' },
  ]

  for (const tc of originDownCases) {
    let clock = 2_000_000
    const origin = `https://origin-${tc.status}.r2-01.example`
    const broker = new RequestBroker({
      now: () => clock,
      circuit5xxThreshold: 2,
      circuitBackoffBaseMs: 100,
      resolve: async () => [PUBLIC_ADDR],
      transport: async () => ({ status: tc.status, headers: {}, body: 'origin down' }),
    })
    const grant = makeBrokerGrant(origin)
    const signal = AbortSignal.timeout(5_000)

    const first = await broker.executeHttp(
      { origin, method: 'GET', pathAndQuery: '/probe/1', probeClass: tc.probeClass },
      grant,
      signal,
    )
    assert.equal(first.status, tc.status)
    assert.equal(broker.isCircuitOpen(origin), false)

    await assert.rejects(
      broker.executeHttp(
        { origin, method: 'GET', pathAndQuery: '/probe/2', probeClass: tc.probeClass },
        grant,
        signal,
      ),
      (err: unknown) => err instanceof BrokerCircuitOpen,
      `HTTP ${tc.status} under probeClass=${tc.probeClass} MUST open origin breaker`,
    )
    const state = broker.getCircuitState(origin)
    assert.equal(state.open, true, `origin breaker must be open after ${tc.status} burst`)
    assert.equal(state.failures5xx, 2, `${tc.status} must be recorded in failures5xx`)
    assert.equal(state.probeInduced5xx, 0, `${tc.status} must NEVER be exempted into probeInduced5xx`)
  }
})

test('R2-01 broker breaker: plain 500/501 under error-inducing probeClass is bounded per window then opens route breaker', async () => {
  let clock = 3_000_000
  let statusToReturn = 500
  const origin = 'https://bounded500.r2-01.example'
  const broker = new RequestBroker({
    now: () => clock,
    circuit5xxThreshold: 2,
    circuitWindowMs: 30_000,
    circuitBackoffBaseMs: 250,
    resolve: async () => [PUBLIC_ADDR],
    transport: async url => {
      if (url.pathname.startsWith('/healthy')) {
        return { status: 200, headers: {}, body: 'ok' }
      }
      return { status: statusToReturn, headers: {}, body: 'parser crash' }
    },
  })
  const grant = makeBrokerGrant(origin)
  const signal = AbortSignal.timeout(5_000)

  // With circuit5xxThreshold=2, per-window probe-induced cap is max(6, 2*3) = 6.
  // First 5 plain 500/501 responses return cleanly as evidence without opening route or origin breakers.
  for (let i = 0; i < 5; i += 1) {
    statusToReturn = i % 2 === 0 ? 500 : 501
    const res = await broker.executeHttp(
      { origin, method: 'GET', pathAndQuery: `/search/${i}`, probeClass: 'sqli_boolean' },
      grant,
      signal,
    )
    assert.equal(res.status, statusToReturn)
    assert.equal(broker.isCircuitOpen(origin), false)
    assert.equal(broker.isRouteCircuitOpen(origin, '/search/*'), false)
  }
  assert.equal(broker.getCircuitState(origin).probeInduced5xx, 5)
  assert.equal(broker.getCircuitState(origin).failures5xx, 0)

  // 6th plain 500 within the window exceeds the per-window cap -> opens the ROUTE breaker (not origin breaker).
  statusToReturn = 500
  await assert.rejects(
    broker.executeHttp(
      { origin, method: 'GET', pathAndQuery: '/search/5', probeClass: 'sqli_boolean' },
      grant,
      signal,
    ),
    (err: unknown) => err instanceof BrokerCircuitOpen && /probe-induced 5xx budget/i.test(err.message),
  )
  assert.equal(broker.isRouteCircuitOpen(origin, '/search/*'), true, 'exceeding probe-induced cap must open route breaker')
  assert.equal(broker.isCircuitOpen(origin), false, 'origin breaker remains closed for sibling routes')

  // Sibling healthy route continues to succeed while /search/* cools down.
  const sibling = await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/healthy' }, grant, signal)
  assert.equal(sibling.status, 200)

  // Non-500/501 5xx (e.g. 507) under an injection probeClass is NOT exempt and trips at threshold5xx=2.
  statusToReturn = 507
  const first507 = await broker.executeHttp(
    { origin, method: 'GET', pathAndQuery: '/storage/1', probeClass: 'sqli_boolean' },
    grant,
    signal,
  )
  assert.equal(first507.status, 507)
  await assert.rejects(
    broker.executeHttp(
      { origin, method: 'GET', pathAndQuery: '/storage/2', probeClass: 'sqli_boolean' },
      grant,
      signal,
    ),
    (err: unknown) => err instanceof BrokerCircuitOpen,
    'non-500/501 5xx must not be exempted by probeClass',
  )
  assert.equal(broker.isRouteCircuitOpen(origin, '/storage/*'), true)
})

// ============================================================================
// 3. Admission explicit-environment-mode lookup + fail-closed catch
// ============================================================================

test('R2-01 admission env-mode: uses storage.hasExplicitEnvironmentMode and catch NEVER grants allowed_environment_contract', () => {
  const runId = 'run-r2-01-env-mode'
  const tenantTag = tenantTagForRun(runId)
  const scopePolicy: ScopePolicy = {
    runId,
    mode: 'staging_isolated',
    targetOrigins: [APP_ORIGIN],
    authOrigins: [],
    assetOrigins: [],
    routeDenylist: [],
    tenantTag,
  }
  const taggedBody = JSON.stringify({ name: `${tenantTag}synthetic-probe`, tenant: `${tenantTag}1` })
  const engine = new RequestAdmissionEngine({ env: {} })

  // 1. Prefers storage.hasExplicitEnvironmentMode(runId) directly (no 500-event scan).
  let hasExplicitCalls = 0
  let eventsAfterCalls = 0
  const explicitCtx = resolveGrantApprovalContext({
    approvalPolicy: 'auto_review',
    scopePolicy,
    storage: {
      run: () => ({ approvalPolicy: 'auto_review', environmentMode: 'staging_isolated' }),
      hasExplicitEnvironmentMode: (id: string) => {
        hasExplicitCalls += 1
        assert.equal(id, runId)
        return true
      },
      eventsAfter: () => {
        eventsAfterCalls += 1
        throw new Error('eventsAfter must NOT be called when hasExplicitEnvironmentMode exists')
      },
    },
  })
  assert.equal(explicitCtx.explicitEnvironmentMode, true)
  assert.equal(explicitCtx.degradation, undefined)
  assert.equal(hasExplicitCalls, 1)
  assert.equal(eventsAfterCalls, 0)

  // 2. When storage throws (either in run() or hasExplicitEnvironmentMode()), catch MUST set
  //    explicitEnvironmentMode=false EVEN WHEN grant.approvalPolicy === undefined, emit a
  //    structured degradation event, and admission MUST NOT grant `allowed_environment_contract`.
  for (const failAt of ['run', 'hasExplicitEnvironmentMode'] as const) {
    const emittedEvents: Array<{ runId: string; kind: string; message: string; detail?: Record<string, unknown> }> = []
    const brokenStore = {
      run: () => {
        if (failAt === 'run') throw new Error('SQLITE_BUSY: database is locked')
        return { approvalPolicy: undefined, environmentMode: 'staging_isolated' as const }
      },
      hasExplicitEnvironmentMode: () => {
        if (failAt === 'hasExplicitEnvironmentMode') throw new Error('SQLITE_CORRUPT: events index unreadable')
        return true
      },
      event: (id: string, kind: string, message: string, detail?: Record<string, unknown>) => {
        emittedEvents.push({ runId: id, kind, message, detail })
      },
    }

    const degradedCtx = resolveGrantApprovalContext({
      approvalPolicy: undefined,
      scopePolicy,
      storage: brokenStore,
    })
    assert.equal(degradedCtx.explicitEnvironmentMode, false, `${failAt}: catch must ALWAYS fail closed`)
    assert.equal(degradedCtx.degradation?.kind, 'admission.env_mode_lookup_degraded')
    assert.equal(degradedCtx.degradation?.runId, runId)
    assert.match(degradedCtx.degradation?.error ?? '', /SQLITE_/)
    assert.equal(emittedEvents.length, 1, `${failAt}: must emit structured degradation event`)
    assert.equal(emittedEvents[0]?.kind, 'admission.env_mode_lookup_degraded')
    assert.equal(emittedEvents[0]?.detail?.explicitEnvironmentMode, false)

    // End-to-end admission check: tagged staging write with approvalPolicy=undefined + throwing store
    // MUST require approval and NEVER return `allowed_environment_contract`!
    let approvalHookCalls = 0
    const decision = engine.admit(
      {
        origin: APP_ORIGIN,
        method: 'POST',
        pathAndQuery: `/api/items?tenant=${tenantTag}1`,
        headers: {
          'content-type': 'application/json',
          'x-kovo-tenant-tag': tenantTag,
          'x-kovo-run-id': runId,
        },
        body: taggedBody,
      },
      {
        origin: APP_ORIGIN,
        tier: 3,
        allowLocalLab: false,
        approvalPolicy: undefined,
        scopePolicy,
        storage: brokenStore,
        canRead: o => o === APP_ORIGIN,
        isStateChangeApproved: () => {
          approvalHookCalls += 1
          return false
        },
      },
    )
    assert.notEqual(
      decision.reasonCode,
      'allowed_environment_contract',
      `${failAt}: storage error must NEVER grant allowed_environment_contract`,
    )
    assert.equal(decision.outcome, 'require_approval', `${failAt}: must fail closed to require_approval`)
    assert.equal(approvalHookCalls, 1, `${failAt}: must route through isStateChangeApproved`)
  }
})
