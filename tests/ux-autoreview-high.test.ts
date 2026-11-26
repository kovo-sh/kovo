import assert from 'node:assert/strict'
import test from 'node:test'
import {
  authorizeStateChange,
  evaluateTier3Approval,
  MAX_KEYWORD_SCAN_CHARS,
} from '../src/server/approval-judge.ts'
import type { Tier3ApprovalInput } from '../src/server/approval-judge.ts'

const APP_ORIGIN = 'https://app.example.com'

test('auto_review auto-approves unauthenticated auth-boundary POST/PUT/PATCH probes when Judge returns escalate_human with low or medium risk', async () => {
  const probes = [
    {
      method: 'POST',
      pathAndQuery: '/_actions/redeemReferralAwardAction',
      bodyPreview: '{"referralCode":"kovo-probe-0001"}',
      riskLevel: 'medium' as const,
    },
    {
      method: 'POST',
      pathAndQuery: '/_actions/createChatAction',
      bodyPreview: '{"title":"kovo-auth-check","projectId":"nonexistent-probe-id"}',
      riskLevel: 'medium' as const,
    },
    {
      method: 'POST',
      pathAndQuery: '/api/comments',
      bodyPreview: '{"body":"kovo-auth-boundary-probe"}',
      riskLevel: 'medium' as const,
    },
    {
      method: 'PATCH',
      pathAndQuery: '/api/projects/probe-id-0001',
      bodyPreview: '{"name":"kovo-probe"}',
      riskLevel: 'low' as const,
    },
    {
      method: 'PUT',
      pathAndQuery: '/api/settings/preferences',
      bodyPreview: '{"theme":"dark"}',
      riskLevel: 'medium' as const,
    },
  ]

  for (const probe of probes) {
    let seenSystemPrompt = ''
    const res = await evaluateTier3Approval({
      policy: 'auto_review',
      origin: APP_ORIGIN,
      method: probe.method,
      pathAndQuery: probe.pathAndQuery,
      personaHandle: null,
      bodyPreview: probe.bodyPreview,
      offline: false,
      llmCall: async ({ systemPrompt }) => {
        seenSystemPrompt = systemPrompt
        return JSON.stringify({
          decision: 'escalate_human',
          riskLevel: probe.riskLevel,
          reason: 'State-changing probe against public endpoint.',
        })
      },
    })

    assert.equal(res.decision, 'approve', `Expected auto-approve for unauth ${probe.method} ${probe.pathAndQuery}`)
    assert.equal(res.decidedBy, 'auto-review:policy')
    assert.equal(res.riskLevel, probe.riskLevel)
    assert.equal(res.originalJudgeDecision, 'escalate_human')
    assert.equal(res.originalRiskLevel, probe.riskLevel)
    assert.equal(res.hostFloor, 'low')
    assert.equal(res.stage, 'safety_judge')
    assert.equal(res.usedLlm, true)
    assert.match(res.reason, /auto_review/i)
    assert.match(res.reason, /non-destructive|auth-boundary/i)
    assert.match(res.reason, /State-changing probe against public endpoint\./)
    assert.equal(res.policyNote, res.reason)

    // Safety Judge system prompt explicitly teaches Option 2 auto_review rubric
    assert.match(seenSystemPrompt, /unauthenticated/i)
    assert.match(seenSystemPrompt, /riskLevel.*"high"|high`-risk/i)
  }
})

test('auto_review still escalates external GitHub mutations and credential/token rotation even on medium Judge risk', async () => {
  const highImpactCases = [
    {
      label: 'external GitHub issue mutation with medium Judge risk',
      method: 'PATCH',
      pathAndQuery: '/api/github/issues/dyad-sh/dyad/1',
      personaHandle: null,
      bodyPreview: '{"state":"closed"}',
      judgeRisk: 'medium' as const,
      expectedSafeguard: /github|third-party/i,
    },
    {
      label: 'external GitHub issue mutation with high Judge risk',
      method: 'PATCH',
      pathAndQuery: '/api/github/issues/dyad-sh/dyad/1',
      personaHandle: 'user_a',
      bodyPreview: '{"body":"probe comment"}',
      judgeRisk: 'high' as const,
      expectedSafeguard: /github|external/i,
    },
    {
      label: 'integration credential/token refresh rotation (medium Judge risk)',
      method: 'POST',
      pathAndQuery: '/api/integrations/neon/refresh',
      personaHandle: null,
      bodyPreview: '{"force":true}',
      judgeRisk: 'medium' as const,
      expectedSafeguard: /credential|token|rotation/i,
    },
    {
      label: 'integration credential/token refresh rotation (high Judge risk)',
      method: 'POST',
      pathAndQuery: '/api/integrations/neon/refresh',
      personaHandle: 'user_a',
      bodyPreview: '{}',
      judgeRisk: 'high' as const,
      expectedSafeguard: /credential|token|rotation|refresh/i,
    },
    {
      label: 'webhook mutation',
      method: 'POST',
      pathAndQuery: '/api/webhooks/outbound',
      personaHandle: null,
      bodyPreview: '{"url":"https://hook.example.org"}',
      judgeRisk: 'medium' as const,
      expectedSafeguard: /webhook|third-party/i,
    },
    {
      label: 'billing/charge execution',
      method: 'POST',
      pathAndQuery: '/api/billing/charge',
      personaHandle: 'user_a',
      bodyPreview: '{"amount":500}',
      judgeRisk: 'medium' as const,
      expectedSafeguard: /billing|payment/i,
    },
    {
      label: 'payout execution',
      method: 'POST',
      pathAndQuery: '/api/payout',
      personaHandle: 'user_a',
      bodyPreview: '{"amount":100}',
      judgeRisk: 'low' as const,
      expectedSafeguard: /payout|billing/i,
    },
    {
      label: 'refund execution',
      method: 'POST',
      pathAndQuery: '/api/orders/123/refund',
      personaHandle: 'user_a',
      bodyPreview: '{"amount":10}',
      judgeRisk: 'medium' as const,
      expectedSafeguard: /refund|billing/i,
    },
    {
      label: 'token revoke',
      method: 'POST',
      pathAndQuery: '/api/oauth/revoke',
      personaHandle: 'user_a',
      bodyPreview: '{"token":"probe"}',
      judgeRisk: 'medium' as const,
      expectedSafeguard: /credential|token|revocation/i,
    },
    {
      label: 'key rotate',
      method: 'POST',
      pathAndQuery: '/api/keys/rotate',
      personaHandle: 'user_a',
      bodyPreview: '{"keyId":"k1"}',
      judgeRisk: 'low' as const,
      expectedSafeguard: /credential|token|rotation/i,
    },
    {
      label: 'destructive delete/destroy/drop route',
      method: 'POST',
      pathAndQuery: '/api/account/delete',
      personaHandle: 'user_a',
      bodyPreview: '{"confirm":true}',
      judgeRisk: 'medium' as const,
      expectedSafeguard: /destructive|deletion/i,
    },
    {
      label: 'destructive destroy route',
      method: 'POST',
      pathAndQuery: '/api/workspaces/1/destroy',
      personaHandle: null,
      bodyPreview: '{"confirm":true}',
      judgeRisk: 'low' as const,
      expectedSafeguard: /destructive|deletion/i,
    },
    {
      label: 'destructive drop route',
      method: 'POST',
      pathAndQuery: '/api/schema/drop',
      personaHandle: null,
      bodyPreview: '{"table":"users"}',
      judgeRisk: 'medium' as const,
      expectedSafeguard: /destructive|deletion/i,
    },
    {
      label: 'authenticated role/privilege change',
      method: 'PATCH',
      pathAndQuery: '/api/orgs/1/members/2/role',
      personaHandle: 'user_a',
      bodyPreview: '{"role":"admin"}',
      judgeRisk: 'medium' as const,
      expectedSafeguard: /privilege|role/i,
    },
  ]

  for (const tc of highImpactCases) {
    const res = await evaluateTier3Approval({
      policy: 'auto_review',
      origin: APP_ORIGIN,
      method: tc.method,
      pathAndQuery: tc.pathAndQuery,
      personaHandle: tc.personaHandle,
      bodyPreview: tc.bodyPreview,
      offline: false,
      llmCall: async () => JSON.stringify({
        decision: 'escalate_human',
        riskLevel: tc.judgeRisk,
        reason: `External or high-impact probe on ${tc.pathAndQuery}.`,
      }),
    })
    assert.equal(res.decision, 'escalate_human', `${tc.label}: must STILL escalate`)
    assert.equal(res.decidedBy, 'operator', `${tc.label}: operator must decide`)
    assert.equal(res.riskLevel, 'high', `${tc.label}: escalated high-impact risk must be high`)
    assert.equal(res.stage, 'safety_judge')
    assert.match(res.reason, tc.expectedSafeguard, `${tc.label}: reason should explain safeguard`)
  }

  // Unauthenticated POST /api/emails matches domain HIGH_RISK_PATH_TOKENS (`emails`),
  // so R2-01's host risk floor keeps it escalated even when Judge returns medium risk.
  const highRiskEmailsRoute = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/emails',
    personaHandle: null,
    bodyPreview: '{"subject":"kovo-auth-boundary-probe"}',
    offline: false,
    llmCall: async () => JSON.stringify({
      decision: 'escalate_human',
      riskLevel: 'medium',
      reason: 'Outbound email route probe.',
    }),
  })
  assert.equal(highRiskEmailsRoute.decision, 'escalate_human')
  assert.equal(highRiskEmailsRoute.decidedBy, 'operator')
  assert.equal(highRiskEmailsRoute.riskLevel, 'high')
  assert.equal(highRiskEmailsRoute.hostFloor, 'high')
  assert.equal(highRiskEmailsRoute.originalJudgeDecision, 'escalate_human')
  assert.equal(highRiskEmailsRoute.originalRiskLevel, 'medium')

  // Generic non-safeguard route with Judge returning riskLevel: 'high' ALWAYS stays escalated.
  const highRiskNonSafeguard = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/createChatAction',
    personaHandle: null,
    bodyPreview: '{"title":"probe"}',
    offline: false,
    llmCall: async () => JSON.stringify({
      decision: 'escalate_human',
      riskLevel: 'high',
      reason: 'High-risk irreversible action detected by judge.',
    }),
  })
  assert.equal(highRiskNonSafeguard.decision, 'escalate_human')
  assert.equal(highRiskNonSafeguard.riskLevel, 'high')
  assert.equal(highRiskNonSafeguard.decidedBy, 'operator')
})

test('auto_review preserves Judge deny verdicts verbatim', async () => {
  const denied = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/createChatAction',
    personaHandle: null,
    bodyPreview: '{"title":"abusive"}',
    offline: false,
    llmCall: async () => JSON.stringify({
      decision: 'deny',
      riskLevel: 'medium',
      reason: 'Disproportionate or abusive probe denied.',
    }),
  })
  assert.equal(denied.decision, 'deny')
  assert.equal(denied.decidedBy, 'auto-review:judge')
  assert.equal(denied.stage, 'safety_judge')
})

test('auto_review keeps ALL Stage 1A hard escalations intact (DELETE, rce_proof, method-override, >64 KiB, compressed, malformed multipart, race burst, missing context)', async () => {
  let llmCalls = 0
  const llmCall = async () => {
    llmCalls += 1
    return JSON.stringify({ decision: 'approve', riskLevel: 'low', reason: 'Should never be called' })
  }

  const hardCases: Array<Partial<Tier3ApprovalInput> & { label: string; method: string; pathAndQuery: string }> = [
    { label: 'DELETE', method: 'DELETE', pathAndQuery: '/api/items/42' },
    { label: 'rce_proof', method: 'POST', pathAndQuery: '/api/render', isRceProof: true, bodyPreview: '{"x":1}' },
    {
      label: 'method-override header',
      method: 'POST',
      pathAndQuery: '/api/items/42',
      headers: { 'X-HTTP-Method-Override': 'DELETE' },
      bodyPreview: '{"x":1}',
    },
    {
      label: 'method-override form body',
      method: 'POST',
      pathAndQuery: '/api/items/42',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      bodyPreview: '_method=DELETE&id=42',
    },
    {
      label: '>64 KiB body',
      method: 'POST',
      pathAndQuery: '/api/items',
      bodyPreview: 'a'.repeat(MAX_KEYWORD_SCAN_CHARS + 1),
    },
    {
      label: 'compressed Content-Encoding body',
      method: 'POST',
      pathAndQuery: '/api/items',
      headers: { 'Content-Encoding': 'gzip' },
      bodyPreview: 'compressed-payload',
    },
    {
      label: 'compressed body flag',
      method: 'POST',
      pathAndQuery: '/api/items',
      hasCompressedBody: true,
      bodyPreview: 'compressed-payload',
    },
    {
      label: 'malformed multipart',
      method: 'POST',
      pathAndQuery: '/api/upload',
      headers: { 'Content-Type': 'multipart/form-data' },
      bodyPreview: 'missing boundary',
    },
    {
      label: 'race burst',
      method: 'POST',
      pathAndQuery: '/_actions/redeemReferralAwardAction',
      personaHandle: null,
      isRaceBurst: true,
      bodyPreview: '{"code":"probe"}',
    },
  ]

  for (const tc of hardCases) {
    const res = await evaluateTier3Approval({
      policy: 'auto_review',
      origin: APP_ORIGIN,
      ...tc,
      offline: false,
      llmCall,
    })
    assert.equal(res.decision, 'escalate_human', `${tc.label}: must hard-escalate`)
    assert.equal(res.stage, 'hard_escalation', `${tc.label}: must stop in Stage 1A hard_escalation`)
    assert.equal(res.riskLevel, 'high', `${tc.label}: hard escalation must be high risk`)
    assert.equal(res.usedLlm, false, `${tc.label}: must never consult LLM`)
  }
  assert.equal(llmCalls, 0)

  // Missing context in authorizeStateChange ALWAYS fails closed (never pre-authorized by pattern).
  const missingCtx = authorizeStateChange({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/42',
    approvedPatterns: [{ origin: APP_ORIGIN, method: 'POST', pathPattern: '/api/items/*' }],
  })
  assert.equal(missingCtx.approved, false)
  assert.equal(missingCtx.via, 'none')
})

test('auto_review fails closed to escalate_human when Safety Judge is offline, unconfigured, malformed, or throws', async () => {
  const base = {
    policy: 'auto_review' as const,
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/redeemReferralAwardAction',
    personaHandle: null,
    bodyPreview: '{"code":"probe"}',
  }

  const offlineRes = await evaluateTier3Approval({ ...base, offline: true })
  assert.equal(offlineRes.decision, 'escalate_human')
  assert.equal(offlineRes.stage, 'fail_safe')

  const unconfiguredRes = await evaluateTier3Approval({ ...base, offline: false })
  assert.equal(unconfiguredRes.decision, 'escalate_human')
  assert.equal(unconfiguredRes.stage, 'fail_safe')

  const malformedRes = await evaluateTier3Approval({
    ...base,
    offline: false,
    llmCall: async () => 'not valid json {{{',
  })
  assert.equal(malformedRes.decision, 'escalate_human')
  assert.equal(malformedRes.stage, 'fail_safe')

  const invalidSchemaRes = await evaluateTier3Approval({
    ...base,
    offline: false,
    llmCall: async () => JSON.stringify({ decision: 'maybe', riskLevel: 'low', reason: 'invalid enum' }),
  })
  assert.equal(invalidSchemaRes.decision, 'escalate_human')
  assert.equal(invalidSchemaRes.stage, 'fail_safe')

  const errorRes = await evaluateTier3Approval({
    ...base,
    offline: false,
    llmCall: async () => { throw new Error('Safety judge upstream timeout') },
  })
  assert.equal(errorRes.decision, 'escalate_human')
  assert.equal(errorRes.stage, 'fail_safe')
})

test('strict policy remains 100% unchanged and always escalates every state-changing Tier-3 probe', async () => {
  let llmCalls = 0
  const llmCall = async () => {
    llmCalls += 1
    return JSON.stringify({ decision: 'approve', riskLevel: 'low', reason: 'Should never run' })
  }

  const strictCases = [
    { method: 'POST', pathAndQuery: '/_actions/redeemReferralAwardAction', personaHandle: null, bodyPreview: '{"code":"probe"}' },
    { method: 'POST', pathAndQuery: '/api/emails', personaHandle: null, bodyPreview: '{}' },
    { method: 'POST', pathAndQuery: '/v1/client/sign_ins', personaHandle: null, bodyPreview: '{}' },
    { method: 'PATCH', pathAndQuery: '/api/github/issues/dyad-sh/dyad/1', personaHandle: 'user_a', bodyPreview: '{"title":"x"}' },
    { method: 'DELETE', pathAndQuery: '/api/items/42', personaHandle: 'user_a' },
  ]

  for (const tc of strictCases) {
    const res = await evaluateTier3Approval({
      policy: 'strict',
      origin: APP_ORIGIN,
      ...tc,
      approvedPatterns: [{ origin: APP_ORIGIN, method: tc.method, pathPattern: '/**' }],
      offline: false,
      llmCall,
    })
    assert.equal(res.decision, 'escalate_human')
    assert.equal(res.decidedBy, 'operator')
    assert.equal(res.stage, 'strict')
    assert.equal(res.usedLlm, false)
  }
  assert.equal(llmCalls, 0)
})
