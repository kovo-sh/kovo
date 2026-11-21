import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { copyFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { newRun, runCommand } from '../src/domain.ts'
import {
  evaluateTier3Approval,
  matchesApprovedEndpointPattern,
  normalizeApprovalPathPattern,
} from '../src/server/approval-judge.ts'
import { Store } from '../src/server/store.ts'

test('normalizeApprovalPathPattern generalizes dynamic IDs and strips query strings', () => {
  assert.equal(normalizeApprovalPathPattern('/api/v1/items/12345'), '/api/v1/items/*')
  assert.equal(
    normalizeApprovalPathPattern('/api/v1/items/550e8400-e29b-41d4-a716-446655440000/notes?limit=10'),
    '/api/v1/items/*/notes',
  )
  assert.equal(normalizeApprovalPathPattern('/api/orgs/org_9a8b7c6d5e4f/members'), '/api/orgs/*/members')
  assert.equal(normalizeApprovalPathPattern('/api/profile/update?tab=bio'), '/api/profile/update')
  assert.equal(normalizeApprovalPathPattern('/'), '/')

  const patterns = [{ origin: 'https://app.example.com', method: 'POST', pathPattern: '/api/v1/items/*' }]
  assert.ok(matchesApprovedEndpointPattern({
    origin: 'https://app.example.com',
    method: 'POST',
    pathAndQuery: '/api/v1/items/99999?dryRun=true',
  }, patterns))
  assert.equal(matchesApprovedEndpointPattern({
    origin: 'https://app.example.com',
    method: 'DELETE',
    pathAndQuery: '/api/v1/items/99999',
  }, patterns), undefined)
  assert.equal(matchesApprovedEndpointPattern({
    origin: 'https://other.example.com',
    method: 'POST',
    pathAndQuery: '/api/v1/items/99999',
  }, patterns), undefined)
})

test('evaluateTier3Approval enforces strict and yolo policies deterministically without LLM calls', async () => {
  let llmCalled = false
  const llmCall = async () => {
    llmCalled = true
    return JSON.stringify({ decision: 'approve', riskLevel: 'low', reason: 'Should not run' })
  }

  const strictRes = await evaluateTier3Approval({
    policy: 'strict',
    origin: 'https://app.example.com',
    method: 'POST',
    pathAndQuery: '/v1/client/sign_ins',
    llmCall,
  })
  assert.equal(strictRes.decision, 'escalate_human')
  assert.equal(strictRes.decidedBy, 'operator')
  assert.equal(strictRes.usedLlm, false)
  assert.equal(llmCalled, false)

  const yoloDelete = await evaluateTier3Approval({
    policy: 'yolo',
    origin: 'https://app.example.com',
    method: 'DELETE',
    pathAndQuery: '/api/billing/subscription',
    hasMultipart: true,
    isRceProof: true,
    llmCall,
  })
  assert.equal(yoloDelete.decision, 'approve')
  assert.equal(yoloDelete.decidedBy, 'auto-yolo')
  assert.equal(yoloDelete.riskLevel, 'low')
  assert.equal(yoloDelete.usedLlm, false)
  assert.equal(llmCalled, false)
})

test('auto_review Stage 1A always escalates DELETE, multipart, rce_proof, and high-risk mutations', async () => {
  let llmCalls = 0
  const llmCall = async () => {
    llmCalls += 1
    return JSON.stringify({ decision: 'approve', riskLevel: 'low', reason: 'Should never be called' })
  }

  const cases = [
    { method: 'DELETE', pathAndQuery: '/api/items/42' },
    { method: 'POST', pathAndQuery: '/api/files', hasMultipart: true },
    { method: 'POST', pathAndQuery: '/api/render', isRceProof: true },
    { method: 'POST', pathAndQuery: '/api/billing/cancel', personaHandle: 'user_a' },
    { method: 'POST', pathAndQuery: '/api/stripe/refund', personaHandle: 'user_a' },
    { method: 'POST', pathAndQuery: '/api/admin/roles', personaHandle: 'user_a' },
    { method: 'POST', pathAndQuery: '/api/account/password/reset', personaHandle: 'user_a' },
    { method: 'POST', pathAndQuery: '/api/settings', personaHandle: 'user_a', bodyPreview: '{"action":"revoke","webhook":"https://x"}' },
  ]

  for (const tc of cases) {
    const res = await evaluateTier3Approval({
      policy: 'auto_review',
      origin: 'https://app.example.com',
      ...tc,
      llmCall,
    })
    assert.equal(res.decision, 'escalate_human', `Expected escalate_human for ${tc.method} ${tc.pathAndQuery}`)
    assert.equal(res.stage, 'hard_escalation')
    assert.equal(res.riskLevel, 'high')
    assert.equal(res.usedLlm, false)
  }
  assert.equal(llmCalls, 0)
})

test('auto_review Stage 1B fast-paths benign unauth POST, read-only GraphQL/search, and approved patterns', async () => {
  let llmCalls = 0
  const llmCall = async () => {
    llmCalls += 1
    return JSON.stringify({ decision: 'escalate_human', riskLevel: 'medium', reason: 'Should not run' })
  }

  const unauthSignIn = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://clerk.example.com',
    method: 'POST',
    pathAndQuery: '/v1/client/sign_ins',
    bodyPreview: '{"identifier":"probe@example.invalid"}',
    llmCall,
  })
  assert.equal(unauthSignIn.decision, 'approve')
  assert.equal(unauthSignIn.decidedBy, 'auto-review:rule')
  assert.equal(unauthSignIn.stage, 'benign_fast_path')

  const unauthChat = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://engine.example.com',
    method: 'POST',
    pathAndQuery: '/v1/chat/completions',
    bodyPreview: '{"model":"test","messages":[]}',
    llmCall,
  })
  assert.equal(unauthChat.decision, 'approve')
  assert.equal(unauthChat.decidedBy, 'auto-review:rule')

  const unauthEmpty = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://api.example.com',
    method: 'POST',
    pathAndQuery: '/api/projects',
    bodyPreview: '{}',
    llmCall,
  })
  assert.equal(unauthEmpty.decision, 'approve')
  assert.equal(unauthEmpty.decidedBy, 'auto-review:rule')

  const authGraphqlQuery = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://api.example.com',
    method: 'POST',
    pathAndQuery: '/graphql',
    personaHandle: 'user_a',
    bodyPreview: '{"query":"query { viewer { id } }"}',
    llmCall,
  })
  assert.equal(authGraphqlQuery.decision, 'approve')
  assert.equal(authGraphqlQuery.decidedBy, 'auto-review:rule')

  const authSearch = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://api.example.com',
    method: 'POST',
    pathAndQuery: '/api/v1/search',
    personaHandle: 'user_a',
    bodyPreview: '{"q":"widgets","limit":5}',
    llmCall,
  })
  assert.equal(authSearch.decision, 'approve')
  assert.equal(authSearch.decidedBy, 'auto-review:rule')

  const patternMatch = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://api.example.com',
    method: 'PATCH',
    pathAndQuery: '/api/v1/notes/777',
    personaHandle: 'user_a',
    bodyPreview: '{"title":"probe"}',
    approvedPatterns: [{ origin: 'https://api.example.com', method: 'PATCH', pathPattern: '/api/v1/notes/*' }],
    llmCall,
  })
  assert.equal(patternMatch.decision, 'approve')
  assert.equal(patternMatch.stage, 'approved_pattern')
  assert.equal(llmCalls, 0)
})

test('auto_review Stage 2 independent Safety Judge handles approve, escalate_human, deny, malformed JSON, and offline fail-safe', async () => {
  // 1. Judge approves low-risk grey-area probe
  const approved = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://api.example.com',
    method: 'POST',
    pathAndQuery: '/api/profile/update',
    personaHandle: 'user_a',
    bodyPreview: '{"displayName":"Guardian Probe"}',
    rationale: 'Verify CSRF protection on profile update.',
    offline: false,
    llmCall: async ({ userPrompt }) => {
      assert.ok(userPrompt.includes('/api/profile/update'))
      return '```json\n{"decision":"approve","riskLevel":"low","reason":"Reversible test-account profile probe."}\n```'
    },
  })
  assert.equal(approved.decision, 'approve')
  assert.equal(approved.decidedBy, 'auto-review:judge')
  assert.equal(approved.usedLlm, true)
  assert.equal(approved.stage, 'safety_judge')

  // 2. Judge escalates uncertain probe
  const escalated = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://api.example.com',
    method: 'POST',
    pathAndQuery: '/api/invites/send',
    personaHandle: 'user_a',
    bodyPreview: '{"to":"ext@example.org"}',
    offline: false,
    llmCall: async () => JSON.stringify({
      decision: 'escalate_human',
      riskLevel: 'medium',
      reason: 'May trigger external email notification.',
    }),
  })
  assert.equal(escalated.decision, 'escalate_human')
  assert.equal(escalated.decidedBy, 'operator')
  assert.equal(escalated.usedLlm, true)

  // 3. Judge denies unsafe probe
  const denied = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://api.example.com',
    method: 'POST',
    pathAndQuery: '/api/broadcast',
    personaHandle: 'user_a',
    bodyPreview: '{"channel":"all","message":"test"}',
    offline: false,
    llmCall: async () => JSON.stringify({
      decision: 'deny',
      riskLevel: 'high',
      reason: 'Broadcasts unsolicited message to all workspace users.',
    }),
  })
  assert.equal(denied.decision, 'deny')
  assert.equal(denied.decidedBy, 'auto-review:judge')
  assert.equal(denied.riskLevel, 'high')

  // 4. Invalid JSON / LLM throw fails safe to escalate_human
  const badJson = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://api.example.com',
    method: 'POST',
    pathAndQuery: '/api/profile/update',
    personaHandle: 'user_a',
    bodyPreview: '{"bio":"x"}',
    offline: false,
    llmCall: async () => 'not valid json at all',
  })
  assert.equal(badJson.decision, 'escalate_human')
  assert.equal(badJson.stage, 'fail_safe')

  const thrown = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://api.example.com',
    method: 'POST',
    pathAndQuery: '/api/profile/update',
    personaHandle: 'user_a',
    bodyPreview: '{"bio":"x"}',
    offline: false,
    llmCall: async () => { throw new Error('Provider timeout') },
  })
  assert.equal(thrown.decision, 'escalate_human')
  assert.equal(thrown.stage, 'fail_safe')

  // 5. Offline fail-safe escalates authenticated state-changing POST and non-empty state-eval POST
  const offlineAuth = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://api.example.com',
    method: 'POST',
    pathAndQuery: '/api/profile/update',
    personaHandle: 'user_a',
    bodyPreview: '{"bio":"probe"}',
    offline: true,
  })
  assert.equal(offlineAuth.decision, 'escalate_human')
  assert.equal(offlineAuth.stage, 'fail_safe')

  const offlineStateEval = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://northstar.example',
    method: 'POST',
    pathAndQuery: '/api/state-eval',
    bodyPreview: '{"probe":"benign-tier3-check"}',
    offline: true,
  })
  assert.equal(offlineStateEval.decision, 'escalate_human')
  assert.equal(offlineStateEval.stage, 'fail_safe')

  // 6. Authenticated GraphQL mutation is NOT fast-pathed -> fails safe offline
  const gqlMutation = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: 'https://api.example.com',
    method: 'POST',
    pathAndQuery: '/graphql',
    personaHandle: 'user_a',
    bodyPreview: '{"query":"mutation { updateProfile(name: \\"x\\") { id } }"}',
    offline: true,
  })
  assert.equal(gqlMutation.decision, 'escalate_human')
})

test('Store supports set_approval_policy, approve_similar_endpoint, approve_all_pending, and audit trail', () => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-approval-store-'))
  const storage = new Store(dir)
  try {
    const project = storage.createProject({
      requestId: randomUUID(),
      name: 'Approval Policy Test',
      seeds: ['https://app.example.com'],
      environment: 'public',
    })
    const parsedNewRun = newRun.parse({
      requestId: randomUUID(),
      projectId: project.id,
      goal: 'Test Tier 3 approval policy commands',
      capabilityTier: 3,
    })
    assert.equal(parsedNewRun.approvalPolicy, 'auto_review')
    const { id: runId } = storage.createRun(parsedNewRun)
    const run0 = storage.run(runId)
    assert.equal(run0.approvalPolicy, 'auto_review')

    storage.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
    const discovered = storage.run(runId)
    storage.command(runCommand.parse({
      requestId: randomUUID(),
      runId,
      action: 'scope',
      assetIds: discovered.candidates.map(c => c.id),
      expectedScopeRevision: discovered.scopeRevision,
      consent: true,
      capabilityTier: 3,
    }))
    const scopedRun = storage.run(runId)
    const worker = storage.makeWorker(scopedRun, 'investigation', scopedRun.candidates[0], 'Worker 1', 'Test Tier 3')

    // 1. Record auto-approved audit entry without pausing worker
    const autoRow = storage.recordAutoApprovalDecision(scopedRun, worker, {
      origin: 'https://app.example.com',
      method: 'POST',
      pathAndQuery: '/v1/client/sign_ins',
      rationale: 'Auth boundary check',
      requestPreview: '{}',
      decision: 'approved',
      decidedBy: 'auto-review:rule',
      riskLevel: 'low',
      policyNote: 'Auto-approved benign unauthenticated sign-in probe.',
    })
    assert.equal(autoRow.status, 'approved')
    assert.equal(autoRow.decidedBy, 'auto-review:rule')
    assert.equal(autoRow.riskLevel, 'low')
    assert.equal(storage.worker(worker.id).status, 'queued')

    // 2. approve_similar_endpoint approves target card, stores pattern, and auto-approves matching pending sibling
    const cardA = storage.createApprovalRequest(scopedRun, worker, {
      origin: 'https://app.example.com',
      method: 'PATCH',
      pathAndQuery: '/api/v1/items/101',
      personaHandle: 'user_a',
      rationale: 'Check IDOR on item 101',
      requestPreview: '{"name":"x"}',
      policyNote: 'Grey-area authenticated write',
      riskLevel: 'medium',
    })
    const cardB = storage.createApprovalRequest(scopedRun, worker, {
      origin: 'https://app.example.com',
      method: 'PATCH',
      pathAndQuery: '/api/v1/items/202',
      personaHandle: 'user_a',
      rationale: 'Check IDOR on item 202',
      requestPreview: '{"name":"y"}',
    })
    const cardC = storage.createApprovalRequest(scopedRun, worker, {
      origin: 'https://app.example.com',
      method: 'DELETE',
      pathAndQuery: '/api/v1/items/303',
      personaHandle: 'user_a',
      rationale: 'Check DELETE authz',
      requestPreview: '{}',
      riskLevel: 'high',
    })

    storage.command(runCommand.parse({
      requestId: randomUUID(),
      runId,
      action: 'approve_similar_endpoint',
      approvalId: cardA.id,
    }))
    assert.equal(storage.getApprovalRequest(runId, cardA.id).status, 'approved')
    assert.equal(storage.getApprovalRequest(runId, cardB.id).status, 'approved')
    assert.equal(storage.getApprovalRequest(runId, cardB.id).decidedBy, 'auto-review:rule')
    assert.equal(storage.getApprovalRequest(runId, cardC.id).status, 'pending')
    const afterPattern = storage.run(runId)
    assert.equal(afterPattern.approvedEndpointPatterns.length, 1)
    assert.equal(afterPattern.approvedEndpointPatterns[0]?.pathPattern, '/api/v1/items/*')

    // 3. approve_all_pending approves remaining pending cards in one transaction
    const cardD = storage.createApprovalRequest(afterPattern, worker, {
      origin: 'https://app.example.com',
      method: 'POST',
      pathAndQuery: '/api/v1/billing/preview',
      rationale: 'Billing preview check',
      requestPreview: '{}',
    })
    storage.command(runCommand.parse({
      requestId: randomUUID(),
      runId,
      action: 'approve_all_pending',
    }))
    assert.equal(storage.getApprovalRequest(runId, cardC.id).status, 'approved')
    assert.equal(storage.getApprovalRequest(runId, cardD.id).status, 'approved')
    assert.equal(storage.listApprovalRequests(runId, 'pending').length, 0)

    // 4. set_approval_policy switches live mid-run; switching to yolo auto-approves pending cards
    storage.command(runCommand.parse({
      requestId: randomUUID(),
      runId,
      action: 'set_approval_policy',
      approvalPolicy: 'strict',
    }))
    assert.equal(storage.run(runId).approvalPolicy, 'strict')

    const pendingInStrict = storage.createApprovalRequest(storage.run(runId), worker, {
      origin: 'https://app.example.com',
      method: 'POST',
      pathAndQuery: '/api/state-eval',
      rationale: 'Pending in strict mode',
      requestPreview: '{}',
    })
    assert.equal(storage.getApprovalRequest(runId, pendingInStrict.id).status, 'pending')

    storage.command(runCommand.parse({
      requestId: randomUUID(),
      runId,
      action: 'set_approval_policy',
      approvalPolicy: 'yolo',
    }))
    assert.equal(storage.run(runId).approvalPolicy, 'yolo')
    const autoApprovedOnSwitch = storage.getApprovalRequest(runId, pendingInStrict.id)
    assert.equal(autoApprovedOnSwitch.status, 'approved')
    assert.equal(autoApprovedOnSwitch.decidedBy, 'auto-yolo')
  } finally {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Store.initV3Schema auto-migrates existing .guardian/dyad-v2-smoke SQLite cleanly', () => {
  const sourceDir = resolve('.guardian/dyad-v2-smoke/data')
  const sourceDb = join(sourceDir, 'guardian.sqlite')
  if (!existsSync(sourceDb)) {
    // Skip gracefully only if smoke DB does not exist in a fresh checkout
    return
  }

  const tempDir = mkdtempSync(join(tmpdir(), 'guardian-migrate-smoke-'))
  try {
    copyFileSync(sourceDb, join(tempDir, 'guardian.sqlite'))
    for (const suffix of ['-wal', '-shm']) {
      if (existsSync(sourceDb + suffix)) {
        copyFileSync(sourceDb + suffix, join(tempDir, 'guardian.sqlite' + suffix))
      }
    }

    const migrated = new Store(tempDir)
    try {
      const runCols = (migrated.client.prepare('PRAGMA table_info(runs)').all() as Array<{ name: string }>).map(r => r.name)
      assert.ok(runCols.includes('approval_policy'))
      assert.ok(runCols.includes('approved_endpoint_patterns'))

      const approvalCols = (migrated.client.prepare('PRAGMA table_info(approval_requests)').all() as Array<{ name: string }>).map(r => r.name)
      assert.ok(approvalCols.includes('policy_note'))
      assert.ok(approvalCols.includes('risk_level'))

      const ws = migrated.listWorkspace()
      for (const proj of ws.projects) {
        const detail = migrated.projectDetail(proj.id)
        for (const r of detail.runs) {
          const full = migrated.run(r.id)
          assert.ok(['auto_review', 'yolo', 'strict'].includes(full.approvalPolicy))
          assert.ok(Array.isArray(full.approvedEndpointPatterns))
        }
      }
    } finally {
      migrated.close()
    }
  } finally {
    rmSync(tempDir, { recursive: true, force: true })
  }
})
