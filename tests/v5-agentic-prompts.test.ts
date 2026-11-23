/**
 * v5.1 agentic-prompts stream: assignment evidence brief, prompt contract injection,
 * batched micro-task guidance, skill slimming, and turn/wall budgets.
 *
 * All fixtures are generic/synthetic: no benchmark/app/route/seed literals.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  ASSIGNMENT_BRIEF_MAX_BYTES,
  buildAssignmentBrief,
  buildAssignmentBriefPacket,
  measureAssignmentBriefBytes,
} from '../src/server/assignment-brief.ts'
import {
  AGENTIC_CONTRACT_LINES,
  AGENTIC_DET_LEAD_LIMIT,
  AGENTIC_MAX_MAX_TURNS,
  AGENTIC_MIN_MAX_TURNS,
  AGENTIC_SPECIALIST_MAX_TURNS,
  AGENTIC_SPECIALIST_WALL_CLOCK_MS,
  AGENTIC_UPGRADE_MAX_TURNS,
  SPECIALIST_PROFILES,
  buildAgenticPromptContext,
  chainPlannerPrompt,
  confirmedRefsFromParentFacts,
  detLeadsFromParentFacts,
  resolveAgenticTurnBudget,
  settlementNudgeTurnFor,
  workerInvestigationPrompt,
} from '../src/server/agent-session.ts'

const origin = 'https://app.example.invalid'

function parse<T = Record<string, unknown>>(text: string): T {
  return JSON.parse(text) as T
}

// ============================================================================
// 1. Assignment evidence brief
// ============================================================================

test('brief: hard byte cap is respected and the result stays valid JSON', () => {
  const routes = Array.from({ length: 200 }, (_, i) => ({
    method: i % 2 ? 'POST' : 'GET',
    path: `/api/tenant/${i}/resource-with-a-long-name/${'x'.repeat(80)}`,
    params: Array.from({ length: 12 }, (_, p) => `parameter_${p}_with_a_long_name`),
    encoding: 'json',
    csrfRequired: i % 3 === 0,
    riskScore: i % 100,
  }))
  const personas = Array.from({ length: 40 }, (_, i) => ({
    handle: `persona_${i}`,
    role: 'tenant_member',
    harvestedIds: Array.from({ length: 10 }, (_, j) => `resource-${i}-${j}`),
  }))
  const baseline = {
    status: 200,
    topLevelKeys: Array.from({ length: 80 }, (_, i) => `top_level_key_${i}`),
    sampleNumericOrStateFields: Object.fromEntries(
      Array.from({ length: 80 }, (_, i) => [`state_field_${i}`, i % 2 === 0 ? i : 'active']),
    ),
  }
  const packet = buildAssignmentBriefPacket({
    missionKind: 'class_scan',
    origin,
    routes,
    linkedRoutes: routes.slice(0, 40),
    personas,
    baseline,
    alreadyConfirmedOnOrigin: Array.from({ length: 40 }, (_, i) => ({
      method: 'GET', path: `/api/confirmed/${i}`, param: 'id', cwe: 'CWE-639',
    })),
    detLead: { probeClass: 'authz_matrix', signalSummary: 'similar responses; no replayable proof' },
    targetCount: 2,
    turnBudget: 9,
  })

  assert.equal(packet.truncated, true)
  assert.ok(packet.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES, `bytes=${packet.bytes}`)
  assert.equal(measureAssignmentBriefBytes(packet.text), packet.bytes)
  const parsed = parse<{ mission: string; origin: string; detLead?: { probeClass: string } }>(packet.text)
  assert.equal(parsed.mission, 'class_scan')
  assert.equal(parsed.origin, origin)
  assert.equal(parsed.detLead?.probeClass, 'authz_matrix', 'det_lead must survive reduction')
})

test('brief: highest-signal ordering puts det_lead first and sorts routes by signal', () => {
  const text = buildAssignmentBrief({
    missionKind: 'det_lead_upgrade',
    origin,
    detLead: {
      probeClass: 'sqli_boolean',
      exchangeId: 'exchange-1',
      signalSummary: 'boolean divergence on control vs probe',
      verifyFailureReason: 'status-only claim',
    },
    routes: [
      { method: 'GET', path: '/api/low', params: ['id'], riskScore: 10 },
      { method: 'POST', path: '/api/high', params: ['accountId', 'amount'], riskScore: 90 },
      { method: 'GET', path: '/api/mid', params: ['q'], riskScore: 50 },
    ],
    linkedRoutes: [{ method: 'GET', path: '/api/linked', params: ['id'], riskScore: 5 }],
    personas: [{ handle: 'user_a', harvestedIds: ['res-1', 'res-2'] }, { handle: 'anon' }],
    baseline: { status: 200, topLevelKeys: ['id', 'state'], sampleNumericOrStateFields: { count: 2, state: 'active' } },
    alreadyConfirmedOnOrigin: [{ method: 'GET', path: '/api/already', param: 'id', cwe: 'CWE-639' }],
  })
  const parsed = parse<{
    routes: Array<{ path: string }>
    linkedRoutes: Array<{ path: string }>
    personas: Array<{ handle: string }>
    alreadyConfirmedOnOrigin: Array<{ path: string }>
  }>(text)

  assert.ok(text.indexOf('"detLead"') < text.indexOf('"routes"'), 'det_lead must render before routes')
  assert.ok(text.indexOf('"routes"') < text.indexOf('"linkedRoutes"'), 'primary routes before linked routes')
  assert.deepEqual(parsed.routes.map(r => r.path), ['/api/high', '/api/mid', '/api/low'])
  assert.deepEqual(parsed.linkedRoutes.map(r => r.path), ['/api/linked'])
  assert.deepEqual(parsed.personas.map(p => p.handle), ['user_a', 'anon'])
  assert.deepEqual(parsed.alreadyConfirmedOnOrigin.map(r => r.path), ['/api/already'])
})

test('brief: no secrets, tokens, or response bodies are rendered', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart'
  const text = buildAssignmentBrief({
    missionKind: 'workflow_skip',
    origin,
    routes: [{
      method: 'POST',
      path: '/api/checkout?token=super-secret-token#fragment',
      params: ['cartId', 'quantity'],
      encoding: 'json',
      csrfRequired: true,
    }],
    personas: [{
      handle: 'user_a',
      harvestedIds: ['order-123', jwt, 'ghp_abcdefghijklmnopqrstuvwxyz', 'sk_live_abcdefghijklmnop'],
    }],
    baseline: {
      status: 200,
      topLevelKeys: ['cartId', 'token', 'body', 'state'],
      sampleNumericOrStateFields: {
        quantity: 1,
        state: 'active',
        apiToken: 'sk_live_abcdefghijklmnop',
        responseBody: '<html>secret markup</html>',
        authorization: `Bearer ${jwt}`,
      },
    },
    detLead: {
      probeClass: 'business_invariant',
      signalSummary: `control vs probe used Bearer ${jwt} and body: <html>raw</html>`,
      verifyFailureReason: 'token=super-secret-token leaked in status-only claim',
    },
  })

  for (const forbidden of [
    'super-secret-token', 'sk_live_', 'ghp_', 'eyJhbGci', '<html>', 'raw</html>',
    'apiToken', 'responseBody', 'authorization', '?token=', '#fragment',
  ]) {
    assert.ok(!text.includes(forbidden), `brief must not include ${forbidden}: ${text}`)
  }
  const parsed = parse<{
    routes: Array<{ path: string; params?: string[] }>
    personas: Array<{ harvestedIds?: string[] }>
    baseline?: { topLevelKeys?: string[]; sampleNumericOrStateFields?: Record<string, unknown> }
  }>(text)
  assert.equal(parsed.routes[0]?.path, '/api/checkout')
  assert.deepEqual(parsed.routes[0]?.params, ['cartId', 'quantity'])
  assert.deepEqual(parsed.personas[0]?.harvestedIds, ['order-123'])
  assert.deepEqual(parsed.baseline?.topLevelKeys, ['cartId', 'state'])
  assert.deepEqual(parsed.baseline?.sampleNumericOrStateFields, { quantity: 1, state: 'active' })
})

test('brief: a custom cap is honored deterministically', () => {
  const input = {
    missionKind: 'second_order' as const,
    origin,
    routes: Array.from({ length: 30 }, (_, i) => ({
      method: 'GET', path: `/api/route/${i}`, params: ['id'], riskScore: i,
    })),
    personas: [{ handle: 'user_a', harvestedIds: ['a', 'b', 'c'] }],
  }
  const first = buildAssignmentBriefPacket(input, 512)
  const second = buildAssignmentBriefPacket(input, 512)
  assert.equal(first.text, second.text, 'reduction must be deterministic')
  assert.ok(first.bytes <= 512)
  assert.ok(first.truncated)
})

// ============================================================================
// 2. Prompt contract injection
// ============================================================================

const detLeadFacts = [
  {
    id: 'fact-low', kind: 'note', origin, summary: 'low signal',
    data: {
      kind: 'det_lead', probeClass: 'xss_context', endpoint: '/api/low', method: 'GET',
      exchangeId: 'ex-low', reason: 'single anomaly', anomalies: [{ type: 'reflection' }],
    },
  },
  {
    id: 'fact-high', kind: 'note', origin, summary: 'high signal',
    data: {
      kind: 'det_lead', probeClass: 'authz_matrix', endpoint: '/api/high', method: 'GET', param: 'id',
      exchangeId: 'ex-high', reason: 'two anomalies plus canary', canaryId: 'canary-1',
      anomalies: [{ type: 'unauthorized_access' }, { type: 'canary_triggered' }],
    },
  },
]

test('specialist prompt: contract, read-only confirmed block, hard-surface block, and top-K det_lead summary', () => {
  const prompt = workerInvestigationPrompt({
    goal: 'defensive authorization review',
    step: {
      id: 'step-1',
      title: 'Cross-tenant read check',
      hypothesis: 'A lower-privileged persona can read another tenant record',
      category: 'broken-access-control',
      skills: ['bola-idor-race'],
      specialistProfile: 'bola-bfla-specialist',
    },
    origins: [origin],
    capabilityTier: 2,
    maxTurns: AGENTIC_SPECIALIST_MAX_TURNS,
    parentFacts: detLeadFacts,
    alreadyConfirmed: [{ method: 'GET', path: '/api/invoices/:id', param: 'id', cwe: 'CWE-639' }],
    unconfirmedHardSurface: [{ method: 'POST', path: '/api/refund', category: 'business-logic', reason: 'workflow step skip' }],
    assignmentBrief: '{"mission":"det_lead_upgrade"}',
  })
  const parsed = parse<{
    settlementNudgeAtTurn: number
    availableSkills: string[]
    agenticContext: {
      contract: string[]
      alreadyConfirmedReadOnly?: { label: string; items: Array<{ path: string }> }
      unconfirmedHardSurface?: { label: string; items: Array<{ path: string }> }
      detLeadSummary?: { label: string; items: Array<{ probeClass: string; endpoint?: string }> }
      microTaskGuidance: Record<string, string>
      evidenceBrief?: string
    }
  }>(prompt)

  assert.deepEqual(parsed.agenticContext.contract, [...AGENTIC_CONTRACT_LINES])
  assert.equal(parsed.agenticContext.alreadyConfirmedReadOnly?.label, 'Already Confirmed (do not duplicate; MAY chain/escalate)')
  assert.equal(parsed.agenticContext.alreadyConfirmedReadOnly?.items[0]?.path, '/api/invoices/:id')
  assert.equal(parsed.agenticContext.unconfirmedHardSurface?.label, 'Unconfirmed Hard Surface')
  assert.equal(parsed.agenticContext.unconfirmedHardSurface?.items[0]?.path, '/api/refund')
  assert.ok(parsed.agenticContext.detLeadSummary)
  assert.ok((parsed.agenticContext.detLeadSummary?.items.length ?? 0) <= AGENTIC_DET_LEAD_LIMIT)
  assert.equal(parsed.agenticContext.detLeadSummary?.items[0]?.probeClass, 'authz_matrix', 'highest-signal lead first')
  assert.equal(parsed.agenticContext.detLeadSummary?.items[0]?.endpoint, '/api/high')
  assert.equal(parsed.agenticContext.evidenceBrief, '{"mission":"det_lead_upgrade"}')
  assert.equal(parsed.settlementNudgeAtTurn, AGENTIC_SPECIALIST_MAX_TURNS - 2)

  const guidance = parsed.agenticContext.microTaskGuidance
  assert.match(guidance.batching ?? '', /request_http_batch/)
  assert.match(guidance.batching ?? '', /4-8/)
  assert.match(guidance.parallelReadOnly ?? '', /parallel|together/)
  assert.match(guidance.assignmentTarget ?? '', /1-3 linked routes/)
  assert.match(guidance.turnBudget ?? '', /8-10/)
  assert.match(guidance.settlement ?? '', /N-2/)
})

test('planner prompt: contract and read-only blocks are injected when data exists', () => {
  const prompt = chainPlannerPrompt({
    goal: 'defensive review',
    roundNo: 2,
    capabilityTier: 2,
    approvedOrigins: [origin],
    activeFacts: [],
    coldDigests: [],
    chainSteps: [],
    alreadyConfirmed: [{ method: 'GET', path: '/api/confirmed', param: 'id', cwe: 'CWE-639' }],
    uncoveredEndpoints: [
      { id: 'e-low', origin, method: 'GET', pathTemplate: '/api/low-risk', riskScore: 10, coveragePct: 100, testedClasses: ['sqli_boolean'] },
      { id: 'e-high', origin, method: 'POST', pathTemplate: '/api/refund', riskScore: 95, coveragePct: 0, testedClasses: [] },
    ],
    detLeads: [{ probeClass: 'authz_matrix', endpoint: '/api/leads', signalSummary: 'no replayable proof' }],
  })
  const parsed = parse<{
    agenticContext: {
      contract: string[]
      alreadyConfirmedReadOnly?: { items: Array<{ path: string }> }
      unconfirmedHardSurface?: { items: Array<{ path: string }> }
      detLeadSummary?: { items: Array<{ probeClass: string }> }
    }
  }>(prompt)
  assert.deepEqual(parsed.agenticContext.contract, [...AGENTIC_CONTRACT_LINES])
  assert.equal(parsed.agenticContext.alreadyConfirmedReadOnly?.items[0]?.path, '/api/confirmed')
  assert.equal(parsed.agenticContext.unconfirmedHardSurface?.items[0]?.path, '/api/refund')
  assert.equal(parsed.agenticContext.detLeadSummary?.items[0]?.probeClass, 'authz_matrix')
})

test('agentic context omits data blocks when no data exists but keeps the contract', () => {
  const context = buildAgenticPromptContext()
  assert.deepEqual(context.contract, [...AGENTIC_CONTRACT_LINES])
  assert.equal('alreadyConfirmedReadOnly' in context, false)
  assert.equal('unconfirmedHardSurface' in context, false)
  assert.equal('detLeadSummary' in context, false)
  assert.ok(context.microTaskGuidance)
})

test('confirmed refs are derived read-only from replay-verified parent facts', () => {
  const refs = confirmedRefsFromParentFacts([
    {
      data: {
        subkind: 'deterministic_engine_confirmed',
        endpoint: '/api/invoices/:id',
        method: 'GET',
        param: 'id',
        vulnClass: 'authz_matrix',
        verdict: 'confirmed',
      },
    },
    {
      data: {
        subkind: 'deterministic_engine_confirmed',
        endpoint: '/api/invoices/:id',
        method: 'GET',
        param: 'id',
        vulnClass: 'authz_matrix',
      },
    },
    { data: { kind: 'det_lead', endpoint: '/api/not-confirmed' } },
  ])
  assert.equal(refs.length, 1, 'duplicates and leads must not enter the confirmed block')
  assert.deepEqual(refs[0], {
    method: 'GET',
    path: '/api/invoices/:id',
    param: 'id',
    probeClass: 'authz_matrix',
  })

  const prompt = workerInvestigationPrompt({
    goal: 'defensive authorization review',
    step: {
      id: 'step-2', title: 'Escalate confirmed read', hypothesis: 'chain the confirmed read into a mutation',
      category: 'broken-access-control', skills: ['bola-idor-race'], specialistProfile: 'bola-bfla-specialist',
    },
    origins: [origin],
    capabilityTier: 2,
    maxTurns: AGENTIC_SPECIALIST_MAX_TURNS,
    parentFacts: [{
      id: 'confirmed-1', kind: 'note', origin, summary: 'replay verified',
      data: { subkind: 'deterministic_engine_confirmed', endpoint: '/api/invoices/:id', method: 'GET', param: 'id' },
    }],
  })
  const parsed = parse<{
    agenticContext: { alreadyConfirmedReadOnly?: { items: Array<{ path: string; method?: string }> } }
  }>(prompt)
  assert.equal(parsed.agenticContext.alreadyConfirmedReadOnly?.items[0]?.path, '/api/invoices/:id')
  assert.equal(parsed.agenticContext.alreadyConfirmedReadOnly?.items[0]?.method, 'GET')
})

test('det_lead derivation ranks anomaly/canary signal and caps the summary', () => {
  const leads = detLeadsFromParentFacts(detLeadFacts)
  assert.equal(leads.length, 2)
  assert.equal(leads[0]?.probeClass, 'authz_matrix')
  assert.equal(leads[0]?.verifyFailureReason, undefined)

  const many = Array.from({ length: 20 }, (_, i) => ({
    id: `f-${i}`, kind: 'note', origin, summary: 'lead',
    data: {
      kind: 'det_lead', probeClass: 'authz_matrix', endpoint: `/api/${i}`, method: 'GET',
      reason: `lead ${i}`, anomalies: Array.from({ length: i % 4 }, () => ({ type: 'a' })),
    },
  }))
  assert.ok(detLeadsFromParentFacts(many).length <= 10)
})

// ============================================================================
// 3. Skill slimming
// ============================================================================

test('specialist prompt advertises only its matching playbooks, not the whole catalog', () => {
  const profile = SPECIALIST_PROFILES['bola-bfla-specialist']
  const prompt = workerInvestigationPrompt({
    goal: 'defensive authorization review',
    step: {
      id: 'step-1', title: 'BOLA check', hypothesis: 'cross-tenant read',
      category: 'broken-access-control', skills: ['bola-idor-race'], specialistProfile: 'bola-bfla-specialist',
    },
    origins: [origin],
    capabilityTier: 2,
    maxTurns: AGENTIC_SPECIALIST_MAX_TURNS,
  })
  const parsed = parse<{ availableSkills: string[] }>(prompt)
  assert.deepEqual(parsed.availableSkills, [...new Set(profile.skills)])
  assert.ok(!parsed.availableSkills.includes('cache-smuggling-desync'))
  assert.ok(parsed.availableSkills.length < 10)
})

// ============================================================================
// 4. Turn / wall budgets
// ============================================================================

test('agentic turn budgets and N-2 settlement nudge are exposed as constants', () => {
  assert.ok(AGENTIC_SPECIALIST_MAX_TURNS >= 8 && AGENTIC_SPECIALIST_MAX_TURNS <= 10)
  assert.ok(AGENTIC_UPGRADE_MAX_TURNS >= 6 && AGENTIC_UPGRADE_MAX_TURNS <= 8)
  assert.ok(AGENTIC_SPECIALIST_WALL_CLOCK_MS >= 75_000 && AGENTIC_SPECIALIST_WALL_CLOCK_MS <= 90_000)
  assert.ok(AGENTIC_MIN_MAX_TURNS <= AGENTIC_UPGRADE_MAX_TURNS)
  assert.ok(AGENTIC_MAX_MAX_TURNS >= AGENTIC_SPECIALIST_MAX_TURNS)
  assert.equal(resolveAgenticTurnBudget('det_lead_upgrade'), AGENTIC_UPGRADE_MAX_TURNS)
  assert.equal(resolveAgenticTurnBudget('chain_step_2'), AGENTIC_UPGRADE_MAX_TURNS)
  assert.equal(resolveAgenticTurnBudget('class_scan'), AGENTIC_SPECIALIST_MAX_TURNS)
  assert.equal(settlementNudgeTurnFor(AGENTIC_SPECIALIST_MAX_TURNS), AGENTIC_SPECIALIST_MAX_TURNS - 2)
  assert.equal(settlementNudgeTurnFor(10), 8)
  assert.equal(settlementNudgeTurnFor(6), 4)
  assert.equal(settlementNudgeTurnFor(1), 1)
})
