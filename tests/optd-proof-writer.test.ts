import test from 'node:test'
import assert from 'node:assert/strict'
import {
  DEFAULT_PROOF_WRITER_BUDGET_CAP_USD,
  DEFAULT_PROOF_WRITER_MAX_TURNS,
  DEFAULT_PROOF_WRITER_WALL_CLOCK_MS,
  MAX_PROOF_WRITER_BODY_PREVIEW_CHARS,
  buildProofWriterSystemPrompt,
  buildProofWriterUserPrompt,
  runProofWriterSpecialist,
  type ProofWriterInput,
} from '../src/server/proof-writer-specialist.ts'
import type { AgentSessionResult, RunAgentSessionOptions } from '../src/server/agent-session.ts'

function baseInput(overrides: Partial<ProofWriterInput> = {}): ProofWriterInput {
  return {
    runId: 'run_optd_1',
    assignmentId: 'asgn_optd_1',
    title: 'Cross-tenant report export via minted bearer token',
    vulnClass: 'dual_tenant_abac',
    oracleFamily: 'dual_tenant_abac',
    reproNotes: 'Actor A mints a scoped bearer token on hop 1 and reads tenant B export on hop 2.',
    targetOrigins: ['https://app.example.test'],
    personasPub: [
      { handle: 'actor_low', role: 'member', tenant: 'tenant_a' },
      { handle: 'victim_owner', role: 'admin', tenant: 'tenant_b' },
    ],
    exchanges: [
      {
        exchangeId: 'ex_1',
        origin: 'https://app.example.test',
        method: 'POST',
        pathAndQuery: '/api/v1/tokens',
        persona: 'actor_low',
        requestHeaders: { 'content-type': 'application/json', authorization: 'Bearer raw-secret-token-value-12345' },
        requestBodyPreview: '{"scope":"reports:read"}',
        status: 201,
        mediaType: 'application/json',
        responseHeaders: { 'content-type': 'application/json', 'set-cookie': 'sid=raw-cookie-val' },
        responseBodyPreview: '{"token":"minted_demo_token_abcdef"}',
      },
      {
        exchangeId: 'ex_2',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: '/api/v1/tenants/tenant_b/reports/latest',
        persona: 'actor_low',
        status: 200,
        mediaType: 'application/json',
        responseBodyPreview: '{"tenant":"tenant_b","records":42}',
      },
    ],
    ...overrides,
  }
}

function makeSessionResult(overrides: Partial<AgentSessionResult> = {}): AgentSessionResult {
  return {
    answer: '',
    turnsUsed: 1,
    settled: false,
    nudgesUsed: 0,
    status: 'completed',
    ...overrides,
  }
}

test('buildProofWriterSystemPrompt is short (<2700 chars), teaches ctx.chain() + valid classes + HMAC/webhook/conservation rules, and has zero recon noise', () => {
  const prompt = buildProofWriterSystemPrompt()
  assert.ok(prompt.length > 200, 'system prompt should be non-empty')
  assert.ok(prompt.length < 2_700, `system prompt length ${prompt.length} must stay < 2700 chars`)

  for (const requiredToken of [
    'ctx.chain',
    'ch.control',
    'ch.hop',
    'ch.step',
    'ch.seal',
    'ch.race',
    'ch.edge',
    'ch.stateTransition',
    'ctx.seal_capability',
    'ctx.hmac_sign',
    'ctx.jwt_sign',
    'ctx.race_burst',
    'ctx.await_async',
    'ch.readback',
    'ch.prove',
    'terminalHopId',
    'dual_tenant_abac',
    'economic_conservation',
    'webhook_forgery',
    'forged_settlement',
    'cross_tenant_write',
    'HMAC_SIGN',
    'draftScript',
    'compilerFailure',
    'confirmed: true',
    'NEVER cap.handle',
    'signed_url',
    'bearer_token',
    'api_token',
    'header_secret',
    'hmac_key',
    'generic_secret',
    'path: urlCap',
    'jsonBody',
  ]) {
    assert.ok(prompt.includes(requiredToken), `system prompt should include ${requiredToken}`)
  }
  assert.match(prompt, /OUTSIDE any hop/i)
  assert.match(prompt, /orphan `hop_\*`/i)
  assert.match(prompt, /returns handle STRING directly/i)
  assert.match(prompt, /NEVER write `cap\.handle`/i)
  assert.match(prompt, /NO leading `\/`/i)
  assert.match(prompt, /ctx\.hmac_sign\(\.\.\.\)` BEFORE\/OUTSIDE `ch\.step`\/`ch\.hop`, NEVER inside a hop/i)
  assert.match(prompt, /HMAC_SIGN.*POST/i)
  assert.match(prompt, /webhook_forgery.*forged_settlement.*ch\.readback/i)
  assert.match(prompt, /economic_conservation.*await ch\.readback\(balanceTarget, \{ as: attacker \}\).*BEFORE.*AND AFTER `ch\.race/i)
  assert.match(prompt, /strictly for denied controls/i)

  for (const forbiddenReconTool of [
    'request_http',
    'browser_visit',
    'search_repo',
    'board_post',
    'record_coverage',
  ]) {
    assert.ok(!prompt.includes(forbiddenReconTool), `system prompt must not include recon/board tool ${forbiddenReconTool}`)
  }
})

test('buildProofWriterUserPrompt caps body previews <= 1500 chars, masks sensitive headers, and includes draftScript + compilerFailure', () => {
  const hugeReq = 'A'.repeat(3_200)
  const hugeRes = 'B'.repeat(4_000)
  const input = baseInput({
    exchanges: [
      {
        exchangeId: 'ex_big',
        origin: 'https://app.example.test',
        method: 'POST',
        pathAndQuery: '/api/v1/export',
        persona: 'actor_low',
        requestHeaders: {
          'content-type': 'application/json',
          authorization: 'Bearer super-secret-should-be-masked',
          cookie: 'session=secret-cookie-value',
          'x-trace-id': 'trace-42',
        },
        requestBodyPreview: hugeReq,
        status: 200,
        mediaType: 'application/json',
        responseHeaders: {
          'set-cookie': 'session=new-secret-cookie',
          'x-export-id': 'exp-99',
        },
        responseBodyPreview: hugeRes,
      },
    ],
    draftScript: 'const ch = ctx.chain({ chainId: "c1", terminalVulnClass: "dual_tenant_abac" });\nawait ch.prove({});',
    compilerWarnings: ['dynamic_id_detected: path segment may vary across replays'],
    compilerFailure: {
      rejectedBy: 'missing_pre_chain_control',
      compositeRejectedBy: 'dag_topology',
      reason: 'Missing denied baseline control exchange',
      detail: 'Add pre-chain arm:"control" call on terminal route before hop_1.',
      missingEvidence: ['preChainControlExchangeIds'],
    },
  })

  const prompt = buildProofWriterUserPrompt(input)
  assert.ok(prompt.includes('https://app.example.test'))
  assert.ok(prompt.includes('actor_low (role=member, tenant=tenant_a)'))
  assert.ok(prompt.includes('draft') || prompt.includes('Draft Script'))
  assert.ok(prompt.includes('missing_pre_chain_control'))
  assert.ok(prompt.includes('compositeRejectedBy: dag_topology'))
  assert.ok(prompt.includes('ChainBuilder'))
  assert.ok(prompt.includes('terminalHopId'))
  assert.ok(prompt.includes('preChainControlExchangeIds'))
  assert.ok(prompt.includes('dynamic_id_detected'))
  assert.ok(prompt.includes('trace-42'))
  assert.ok(prompt.includes('exp-99'))

  // Sensitive headers must be redacted.
  assert.ok(!prompt.includes('super-secret-should-be-masked'))
  assert.ok(!prompt.includes('secret-cookie-value'))
  assert.ok(!prompt.includes('new-secret-cookie'))

  // Body previews must be strictly capped <= 1500 chars.
  assert.ok(!prompt.includes('A'.repeat(MAX_PROOF_WRITER_BODY_PREVIEW_CHARS + 1)))
  assert.ok(!prompt.includes('B'.repeat(MAX_PROOF_WRITER_BODY_PREVIEW_CHARS + 1)))
  assert.ok(prompt.includes('…[truncated]'))

  // Action section reinforces ch.seal string return (NEVER cap.handle) + signed_url pattern.
  assert.match(prompt, /returns the handle STRING directly/i)
  assert.match(prompt, /NEVER `cap\.handle`/i)
  assert.ok(prompt.includes('signed_url'))
  assert.ok(prompt.includes('path: urlCap'))
})

test('runProofWriterSpecialist short-circuits immediately on confirmed: true with minimal toolset only', async () => {
  let capturedOptions: RunAgentSessionOptions | undefined
  let verifyCalls = 0
  let turn2Attempted = false

  const result = await runProofWriterSpecialist(
    {
      profiles: [],
      runKovoVerify: async args => {
        verifyCalls += 1
        assert.ok(args.script.includes('ch.prove'))
        assert.equal(args.vulnClass, 'dual_tenant_abac')
        return { confirmed: true, findingId: 'finding_confirmed_42' }
      },
      sessionRunner: async opts => {
        capturedOptions = opts
        opts.beforeCall?.()
        opts.onUsage?.({ inputTokens: 400, outputTokens: 150, costUsd: 0.02 })
        opts.onTurn?.(1, opts.maxTurns ?? 6, false)

        const verifyOut = await opts.handlers?.kovo_verify?.(
          { script: 'const ch = ctx.chain({ chainId: "c1", terminalVulnClass: "dual_tenant_abac" }); await ch.prove({});', runtime: 'ts' },
          opts.signal,
        )
        assert.equal((verifyOut as { confirmed?: boolean }).confirmed, true)
        assert.equal(opts.signal.aborted, true, 'signal must abort immediately on confirmation')

        // Simulate runner attempting a second turn — must abort/throw before calling LLM.
        if (!opts.signal.aborted) {
          turn2Attempted = true
        } else {
          throw new Error('AbortError: session aborted')
        }
        return makeSessionResult({ turnsUsed: 2 })
      },
    },
    baseInput(),
  )

  assert.ok(capturedOptions, 'sessionRunner should be invoked')
  assert.equal(capturedOptions.maxTurns, DEFAULT_PROOF_WRITER_MAX_TURNS)
  assert.equal(capturedOptions.wallClockMs, DEFAULT_PROOF_WRITER_WALL_CLOCK_MS)
  assert.equal(capturedOptions.compaction, false)
  assert.equal(capturedOptions.enableSettlement, false)
  assert.equal(capturedOptions.requireCompleteIntent, false)

  // Strictly minimal toolset: ONLY kovo_verify + complete_intent.
  const handlerKeys = Object.keys(capturedOptions.handlers ?? {}).sort()
  assert.deepEqual(handlerKeys, ['complete_intent', 'kovo_verify'])

  assert.equal(turn2Attempted, false)
  assert.equal(verifyCalls, 1)
  assert.equal(result.confirmed, true)
  assert.equal(result.findingId, 'finding_confirmed_42')
  assert.equal(result.attempts, 1)
  assert.equal(result.turns, 1)
  assert.equal(result.spendUsd, 0.02)
  assert.equal(result.error, undefined)
})

test('runProofWriterSpecialist enforces $0.25 micro-budget cap in beforeCall and forwards usage', async () => {
  const forwardedUsage: Array<{ costUsd?: number; inputTokens?: number; outputTokens?: number }> = []
  let llmCallsAttempted = 0

  const result = await runProofWriterSpecialist(
    {
      profiles: [],
      onUsage: u => { forwardedUsage.push(u) },
      runKovoVerify: async () => ({
        confirmed: false,
        rejectedBy: 'dag_topology',
        reason: 'orphan_hop',
        detail: 'Hop 1 is not linked to terminal hop.',
      }),
      sessionRunner: async opts => {
        // Turn 1: spend $0.14 (under $0.25 cap)
        opts.beforeCall?.()
        llmCallsAttempted += 1
        opts.onUsage?.({ inputTokens: 1_000, outputTokens: 300, costUsd: 0.14 })
        opts.onTurn?.(1, opts.maxTurns ?? 6, false)
        await opts.handlers?.kovo_verify?.({ script: 'await ctx.prove_composite({})', runtime: 'ts' }, opts.signal)

        // Turn 2: spend $0.12 (cumulative $0.26 >= $0.25 cap)
        opts.beforeCall?.()
        llmCallsAttempted += 1
        opts.onUsage?.({ inputTokens: 1_100, outputTokens: 350, costUsd: 0.12 })
        opts.onTurn?.(2, opts.maxTurns ?? 6, false)
        await opts.handlers?.kovo_verify?.({ script: 'await ctx.prove_composite({})', runtime: 'ts' }, opts.signal)

        // Turn 3: beforeCall must throw and abort before making a 3rd LLM call.
        opts.beforeCall?.()
        llmCallsAttempted += 1
        return makeSessionResult({ turnsUsed: 3 })
      },
    },
    baseInput(),
  )

  assert.equal(llmCallsAttempted, 2, 'must stop before 3rd LLM call once spend >= $0.25')
  assert.equal(forwardedUsage.length, 2)
  assert.equal(result.confirmed, false)
  assert.equal(result.attempts, 2)
  assert.equal(result.turns, 2)
  assert.ok(Math.abs(result.spendUsd - 0.26) < 1e-9)
  assert.ok(result.spendUsd >= DEFAULT_PROOF_WRITER_BUDGET_CAP_USD)
  assert.equal(result.lastRejection?.rejectedBy, 'dag_topology')
  assert.equal(result.lastRejection?.reason, 'orphan_hop')
  assert.ok(result.error?.startsWith('budget_cap_exceeded:'), `expected budget_cap_exceeded error, got ${result.error}`)
})

test('runProofWriterSpecialist feeds draftScript + compilerFailure into prompt and confirms after repair turn', async () => {
  let capturedPrompt = ''
  let capturedHandlers: string[] = []
  let attemptCount = 0

  const result = await runProofWriterSpecialist(
    {
      profiles: [],
      runKovoVerify: async args => {
        attemptCount += 1
        if (attemptCount === 1) {
          return {
            confirmed: false,
            rejectedBy: 'missing_hmac_attestation',
            reason: 'unsigned_webhook_body',
            detail: 'Use ctx.hmac_sign with sealed hmac_key.',
            missingEvidence: ['derived_crypto_binding'],
          }
        }
        assert.ok(args.script.includes('ctx.hmac_sign'))
        return { confirmed: true, findingId: 'finding_repaired_9' }
      },
      sessionRunner: async opts => {
        capturedPrompt = opts.prompt
        capturedHandlers = Object.keys(opts.handlers ?? {}).sort()

        opts.beforeCall?.()
        opts.onUsage?.({ inputTokens: 500, outputTokens: 120, costUsd: 0.03 })
        opts.onTurn?.(1, opts.maxTurns ?? 6, false)
        const r1 = await opts.handlers?.kovo_verify?.({ script: 'draft_attempt_1()' }, opts.signal)
        assert.equal((r1 as { rejectedBy?: string }).rejectedBy, 'missing_hmac_attestation')

        opts.beforeCall?.()
        opts.onUsage?.({ inputTokens: 600, outputTokens: 150, costUsd: 0.04 })
        opts.onTurn?.(2, opts.maxTurns ?? 6, false)
        await opts.handlers?.kovo_verify?.({ script: 'await ctx.hmac_sign({ secretHandle: cap.handle, payload })' }, opts.signal)
        throw new Error('aborted after confirm')
      },
    },
    baseInput({
      draftScript: '// Stage 2a draft\nconst ch = ctx.chain({ chainId: "c1", terminalVulnClass: "webhook_forgery" })',
      compilerFailure: {
        rejectedBy: 'missing_hmac_attestation',
        reason: 'Compiler cannot synthesize HMAC signature automatically',
        detail: 'Seal hmac_key and call ctx.hmac_sign.',
        missingEvidence: ['derived_crypto_binding'],
      },
    }),
  )

  assert.deepEqual(capturedHandlers, ['complete_intent', 'kovo_verify'])
  assert.ok(capturedPrompt.includes('// Stage 2a draft'))
  assert.ok(capturedPrompt.includes('missing_hmac_attestation'))
  assert.ok(capturedPrompt.includes('derived_crypto_binding'))
  assert.equal(result.confirmed, true)
  assert.equal(result.findingId, 'finding_repaired_9')
  assert.equal(result.attempts, 2)
  assert.equal(result.turns, 2)
  assert.ok(Math.abs(result.spendUsd - 0.07) < 1e-9)
})

test('runProofWriterSpecialist respects maxTurns, returns structured lastRejection, and reports timeout/abort cleanly', async () => {
  // 1. Respects custom maxTurns=3 and returns structured lastRejection + max_turns_reached error.
  let seenMaxTurns: number | undefined
  const turnLimitRes = await runProofWriterSpecialist(
    {
      profiles: [],
      runKovoVerify: async () => ({
        confirmed: false,
        rejectedBy: 'terminal_class_unmapped',
        reason: 'Invalid terminalVulnClass',
        detail: 'Map to dual_tenant_abac.',
      }),
      sessionRunner: async opts => {
        seenMaxTurns = opts.maxTurns
        for (let t = 1; t <= (opts.maxTurns ?? 6); t += 1) {
          opts.beforeCall?.()
          opts.onUsage?.({ inputTokens: 300, outputTokens: 80, costUsd: 0.01 })
          opts.onTurn?.(t, opts.maxTurns ?? 6, false)
          await opts.handlers?.kovo_verify?.({ script: `attempt_${t}()` }, opts.signal)
        }
        return makeSessionResult({ turnsUsed: opts.maxTurns ?? 3, status: 'turn_limit' })
      },
    },
    baseInput({ maxTurns: 3 }),
  )

  assert.equal(seenMaxTurns, 3)
  assert.equal(turnLimitRes.confirmed, false)
  assert.equal(turnLimitRes.turns, 3)
  assert.equal(turnLimitRes.attempts, 3)
  assert.deepEqual(turnLimitRes.lastRejection, {
    rejectedBy: 'terminal_class_unmapped',
    reason: 'Invalid terminalVulnClass',
    detail: 'Map to dual_tenant_abac.',
  })
  assert.equal(turnLimitRes.error, 'max_turns_reached: 3/3')

  // 2. Wall-clock rotation returns structured timeout error.
  const timeoutRes = await runProofWriterSpecialist(
    {
      profiles: [],
      runKovoVerify: async () => ({ confirmed: false, rejectedBy: 'timeout_oracle', reason: 'slow' }),
      sessionRunner: async opts => {
        opts.onTurn?.(1, opts.maxTurns ?? 6, false)
        return makeSessionResult({ turnsUsed: 1, status: 'wall_clock_rotated' })
      },
    },
    baseInput({ wallClockMs: 5_000 }),
  )
  assert.equal(timeoutRes.confirmed, false)
  assert.equal(timeoutRes.error, 'wall_clock_timeout: exceeded 5000ms')

  // 3. Already-aborted parent signal returns structured abort error immediately without invoking sessionRunner.
  let calledOnPreAbort = false
  const preAborted = new AbortController()
  preAborted.abort('cancelled')
  const abortRes = await runProofWriterSpecialist(
    {
      profiles: [],
      signal: preAborted.signal,
      runKovoVerify: async () => ({ confirmed: false }),
      sessionRunner: async () => {
        calledOnPreAbort = true
        return makeSessionResult()
      },
    },
    baseInput(),
  )
  assert.equal(calledOnPreAbort, false)
  assert.equal(abortRes.confirmed, false)
  assert.equal(abortRes.error, 'aborted')

  // 4. Preserves compositeRejectedBy on both result and lastRejection for downstream Stage 2b handling.
  const compositeRejRes = await runProofWriterSpecialist(
    {
      profiles: [],
      runKovoVerify: async () => ({
        confirmed: false,
        rejectedBy: 'composite_receipt',
        compositeRejectedBy: 'terminal_impact_unproven',
        reason: 'composite_stage_rejected',
        detail: 'Terminal exchange only minted a signed URL.',
      }),
      sessionRunner: async opts => {
        opts.beforeCall?.()
        opts.onTurn?.(1, opts.maxTurns ?? 6, false)
        await opts.handlers?.kovo_verify?.({ script: 'await ch.prove({})', runtime: 'ts' }, opts.signal)
        return makeSessionResult({ turnsUsed: 1 })
      },
    },
    baseInput(),
  )
  assert.equal(compositeRejRes.confirmed, false)
  assert.equal(compositeRejRes.compositeRejectedBy, 'terminal_impact_unproven')
  assert.equal(compositeRejRes.lastRejection?.compositeRejectedBy, 'terminal_impact_unproven')
  assert.equal(compositeRejRes.lastRejection?.rejectedBy, 'composite_receipt')
})
