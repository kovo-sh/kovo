/**
 * v7 guardian-verify-default — verifies `guardian_verify` is exposed on every specialist bundle
 * when registered (Docker backend) and clearly prioritized ahead of legacy `verify_replay_spec`
 * and `propose_chain_finding` across tool ordering, descriptions, system instructions, and repair
 * feedback.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  GUARDIAN_VERIFY_TOOL_DESCRIPTION,
  SPECIALIST_COMMON_TOOLS,
  SPECIALIST_PROFILES,
  buildWorkerTools,
  filterHandlersForSpecialist,
  proofToolHandlerNames,
  verifierRepairFeedback,
  withVerifierRepairFeedback,
  workerSessionInstructions,
} from '../src/server/agent-session.ts'
import type { WorkerToolHandlers } from '../src/server/agent-session.ts'
import { agentProofAttribution } from '../src/server/exec-verify.ts'
import { buildAgentScriptReceipt, verifyReceipt, type ScriptProofExchange } from '../src/server/proof-receipt.ts'

function fullHandlers(withGuardianVerify: boolean): WorkerToolHandlers {
  const noop = async () => ({ ok: true })
  return {
    ...(withGuardianVerify ? { guardian_verify: noop } : {}),
    verify_replay_spec: noop,
    propose_chain_finding: noop,
    update_proposed_finding: noop,
    prove_authz_read_diff: noop,
    prove_state_mutation_diff: noop,
    prove_business_invariant: noop,
    prove_canary_or_redirect: noop,
    request_http: noop,
    complete_intent: noop,
  }
}

test('guardian_verify is exposed on every specialist profile and prioritized before verify_replay_spec', () => {
  const gvIdx = SPECIALIST_COMMON_TOOLS.indexOf('guardian_verify')
  const vrsIdx = SPECIALIST_COMMON_TOOLS.indexOf('verify_replay_spec')
  assert.ok(gvIdx >= 0 && vrsIdx >= 0 && gvIdx < vrsIdx, 'guardian_verify must precede verify_replay_spec in SPECIALIST_COMMON_TOOLS')

  const handlers = fullHandlers(true)
  for (const [id, profile] of Object.entries(SPECIALIST_PROFILES)) {
    const scoped = filterHandlersForSpecialist(handlers, profile)
    assert.equal(typeof scoped.guardian_verify, 'function', `${id} must expose guardian_verify`)
    for (const compiler of proofToolHandlerNames) {
      assert.equal(scoped[compiler], undefined, `${id} must hide JSON compiler ${compiler} when guardian_verify is active`)
    }
    const tools = buildWorkerTools(scoped, v => v, AbortSignal.timeout(5_000), 64 * 1024, () => {})
    const names = tools.map(t => t.name)
    const gIdx = names.indexOf('guardian_verify')
    const pIdx = names.indexOf('propose_chain_finding')
    const vIdx = names.indexOf('verify_replay_spec')
    assert.ok(gIdx >= 0, `${id} registers guardian_verify`)
    assert.ok(gIdx < pIdx && gIdx < vIdx, `${id} registers guardian_verify before propose_chain_finding and verify_replay_spec`)
  }
})

test('tool descriptions mark verify_replay_spec and propose_chain_finding as legacy fallback only when guardian_verify is active', () => {
  const withTools = buildWorkerTools(fullHandlers(true), v => v, AbortSignal.timeout(5_000), 64 * 1024, () => {})
  const withVrs = withTools.find(t => t.name === 'verify_replay_spec')!
  const withPropose = withTools.find(t => t.name === 'propose_chain_finding')!
  assert.match(withVrs.description, /LEGACY FALLBACK.*guardian_verify/i)
  assert.match(withPropose.description, /LEGACY FALLBACK.*guardian_verify/i)
  assert.match(withPropose.description, /proof_kind="agent_script"/)

  const withoutTools = buildWorkerTools(fullHandlers(false), v => v, AbortSignal.timeout(5_000), 64 * 1024, () => {})
  const withoutVrs = withoutTools.find(t => t.name === 'verify_replay_spec')!
  const withoutPropose = withoutTools.find(t => t.name === 'propose_chain_finding')!
  assert.doesNotMatch(withoutVrs.description, /LEGACY FALLBACK/)
  assert.doesNotMatch(withoutPropose.description, /LEGACY FALLBACK/)
})

test('workerSessionInstructions and repair feedback steer active sessions to guardian_verify', () => {
  const active = workerSessionInstructions('worker-investigation', { hasGuardianVerify: true })
  assert.match(active, /PRIMARY PROOF CONTRACT: `guardian_verify` is active/)
  assert.match(active, /proof_kind="agent_script"/)
  assert.match(active, /Do NOT call legacy `verify_replay_spec` or `propose_chain_finding` with `http_chain`/)

  const fallback = workerSessionInstructions('worker-investigation', { hasGuardianVerify: false })
  assert.doesNotMatch(fallback, /PRIMARY PROOF CONTRACT/)
  assert.match(fallback, /guardian_verify/)

  const wrapped = withVerifierRepairFeedback({ verdict: 'dismissed', controlPassed: false, spaCatchallMatched: true }, true)
  const repair = verifierRepairFeedback(wrapped, true)
  assert.ok(repair)
  assert.match(repair.suggestedFix ?? '', /guardian_verify/)
  assert.match(GUARDIAN_VERIFY_TOOL_DESCRIPTION, /BOTH proves AND persists the confirmed finding/i)
})

const ORIGIN = 'https://app.example.invalid'

function httpChainSpec() {
  return {
    version: 1,
    kind: 'http_chain',
    origin: ORIGIN,
    title: 'Cross-tenant invoice read',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Cross-tenant read of another customer record.',
    impact: 'Unauthorized invoice read.',
    remediation: 'Enforce tenant ownership check.',
    recheckInstructions: 'Replay cross-tenant GET.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "200", expected: "403" }',
    steps: [
      { id: 'c', role: 'control', description: 'denied control', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/invoices/0' } },
      { id: 'p', role: 'probe', description: 'cross-tenant probe', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/invoices/101', persona: 'user_b' } },
    ],
  }
}

function staticAstSpec() {
  return {
    version: 1,
    kind: 'static_ast_proof',
    origin: ORIGIN,
    title: 'Static sink trace',
    category: 'injection-input',
    cwe: 'CWE-1336',
    severity: 'high',
    severityRationale: 'Source-to-sink trace in mounted repo.',
    impact: 'Template evaluation sink.',
    remediation: 'Avoid dynamic template compile.',
    recheckInstructions: 'Re-run AST rule.',
    repo: 'app',
    file: 'src/render.ts',
    startLine: 10,
    endLine: 15,
    engine: 'opengrep',
    ruleOrPattern: 'template.compile',
    sourceToSinkTrace: 'req.body.tpl -> compile()',
    runtimeProofGap: 'Tier 0 source-only audit.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "match", expected: "no match" }',
  }
}

test('when guardian_verify is active, propose_chain_finding and verify_replay_spec reject runtime specs and allow static_ast_proof', async () => {
  let proposeCalls = 0
  let verifyCalls = 0
  const activeTools = buildWorkerTools({
    guardian_verify: async () => ({ confirmed: true, attempts: [] }),
    propose_chain_finding: async () => { proposeCalls += 1; return { ok: true } },
    verify_replay_spec: async () => { verifyCalls += 1; return { ok: true } },
  }, v => v, AbortSignal.timeout(5_000), 64 * 1024, () => {})

  const proposeTool = activeTools.find(t => t.name === 'propose_chain_finding')!
  const verifyTool = activeTools.find(t => t.name === 'verify_replay_spec')!

  const rejectedPropose = await proposeTool.execute({
    replaySpec: httpChainSpec(),
    counterevidence: 'Could be intentionally public invoice.',
    confidenceRationale: 'Owner-scoped fields returned across tenants.',
  } as never, {} as never, { abortSignal: AbortSignal.timeout(5_000) } as never) as { isError?: boolean; output: Array<{ text?: string }> }
  assert.equal(rejectedPropose.isError, true)
  assert.match(rejectedPropose.output[0]?.text ?? '', /guardian_verify\(script=/)
  assert.equal(proposeCalls, 0, 'legacy handler must never execute for runtime specs while guardian_verify is active')

  const rejectedVerify = await verifyTool.execute({
    spec: httpChainSpec(),
  } as never, {} as never, { abortSignal: AbortSignal.timeout(5_000) } as never) as { isError?: boolean; output: Array<{ text?: string }> }
  assert.equal(rejectedVerify.isError, true)
  assert.match(rejectedVerify.output[0]?.text ?? '', /guardian_verify\(script=/)
  assert.equal(verifyCalls, 0)

  // static_ast_proof remains allowed even while guardian_verify is active
  const allowedStatic = await proposeTool.execute({
    replaySpec: staticAstSpec(),
    counterevidence: 'Route might be unreachable behind middleware.',
    confidenceRationale: 'Direct handler invokes template compiler.',
  } as never, {} as never, { abortSignal: AbortSignal.timeout(5_000) } as never) as { isError?: boolean }
  assert.notEqual(allowedStatic.isError, true)
  assert.equal(proposeCalls, 1)

  // When guardian_verify is absent (local-jq / replay-only), runtime http_chain remains allowed
  let fallbackCalls = 0
  const fallbackTools = buildWorkerTools({
    verify_replay_spec: async () => { fallbackCalls += 1; return { ok: true } },
  }, v => v, AbortSignal.timeout(5_000), 64 * 1024, () => {})
  const fallbackVerify = await fallbackTools.find(t => t.name === 'verify_replay_spec')!.execute({
    spec: httpChainSpec(),
  } as never, {} as never, { abortSignal: AbortSignal.timeout(5_000) } as never) as { isError?: boolean }
  assert.notEqual(fallbackVerify.isError, true)
  assert.equal(fallbackCalls, 1)
})

test('guardian_verify ProofReceipt cleanly supports BOLA (CWE-639) boundary claims and SSTI (CWE-1336) evaluated expressions with anti-reflection', () => {
  // 1. BOLA via ctx.prove_access_boundary (`kind: 'boundary'`)
  const bolaExchanges: ScriptProofExchange[] = [
    {
      exchangeId: 'ex-ctl', method: 'GET', pathAndQuery: '/api/v1/invoices/101', origin: ORIGIN,
      status: 403, personaHandle: 'anonymous', actorRoleLabel: 'anonymous', body: '{"error":"forbidden"}',
    },
    {
      exchangeId: 'ex-prb', method: 'GET', pathAndQuery: '/api/v1/invoices/101', origin: ORIGIN,
      status: 200, personaHandle: 'member_b', actorRoleLabel: 'member (tenant-b)',
      body: '{"id":"inv-101","owner_id":"owner-a","tenant_id":"tenant-a","email":"alice@tenant-a.example","total":4900}',
    },
  ]
  const bolaBuilt = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Cross-tenant invoice BOLA read',
    exchanges: bolaExchanges,
    claims: [{ kind: 'boundary', boundaryClass: 'access', controlExchangeId: 'ex-ctl', probeExchangeId: 'ex-prb', expectControlDenied: true }],
  })
  assert.ok(bolaBuilt, 'boundary claim must build a BOLA ProofReceipt')
  assert.equal(bolaBuilt.receipt.vulnClass, 'bola')
  assert.equal(agentProofAttribution(bolaBuilt.receipt.vulnClass).cwe, 'CWE-639')
  const bolaVerdict = verifyReceipt(bolaBuilt.receipt, bolaBuilt.transcript)
  assert.equal(bolaVerdict.confirmed, true, bolaVerdict.reason)

  // 2. SSTI via ctx.prove_injection_differential (paired non-reflected `body_contains`)
  const sstiExchanges: ScriptProofExchange[] = [
    {
      exchangeId: 'ex-c', method: 'GET', pathAndQuery: '/api/v1/reports/render?tpl=hello', origin: ORIGIN,
      status: 200, body: '<h1>hello</h1>',
    },
    {
      exchangeId: 'ex-p', method: 'GET', pathAndQuery: '/api/v1/reports/render?tpl=%7B%7B739*740%7D%7D', origin: ORIGIN,
      status: 200, body: '<h1>546860</h1>',
    },
  ]
  const sstiBuilt = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Report SSTI template evaluation',
    exchanges: sstiExchanges,
    claims: [
      { kind: 'body_contains', exchangeId: 'ex-c', text: '546860', absent: true },
      { kind: 'body_contains', exchangeId: 'ex-p', text: '546860', absent: false, message: 'ssti evaluated marker' },
    ],
  })
  assert.ok(sstiBuilt, 'paired evaluated-expression claims must build an SSTI ProofReceipt')
  assert.equal(sstiBuilt.receipt.vulnClass, 'ssti')
  assert.equal(agentProofAttribution(sstiBuilt.receipt.vulnClass).cwe, 'CWE-1336')
  const sstiVerdict = verifyReceipt(sstiBuilt.receipt, sstiBuilt.transcript)
  assert.equal(sstiVerdict.confirmed, true, sstiVerdict.reason)

  // 3. Anti-reflection: raw reflection where the request itself contained "546860" MUST fail closed
  const reflectedExchanges: ScriptProofExchange[] = [
    sstiExchanges[0]!,
    {
      exchangeId: 'ex-p', method: 'GET', pathAndQuery: '/api/v1/reports/render?tpl=546860', origin: ORIGIN,
      status: 200, body: '<h1>546860</h1>',
    },
  ]
  const reflectedBuilt = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Reflected echo is not SSTI',
    exchanges: reflectedExchanges,
    claims: [
      { kind: 'body_contains', exchangeId: 'ex-c', text: '546860', absent: true },
      { kind: 'body_contains', exchangeId: 'ex-p', text: '546860', absent: false, message: 'ssti' },
    ],
  })
  assert.ok(reflectedBuilt)
  const reflectedVerdict = verifyReceipt(reflectedBuilt.receipt, reflectedBuilt.transcript)
  assert.equal(reflectedVerdict.confirmed, false, 'raw reflection must fail closed')
})
