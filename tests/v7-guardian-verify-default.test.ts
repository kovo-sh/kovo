/**
 * v7 guardian-verify-default — verifies `guardian_verify` is exposed on every specialist bundle
 * when registered (Docker backend) and clearly prioritized ahead of legacy `verify_replay_spec`
 * and `propose_chain_finding` across tool ordering, descriptions, system instructions, and repair
 * feedback.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { statSync } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  GUARDIAN_VERIFY_TOOL_DESCRIPTION,
  GUARDIAN_VERIFY_USAGE_HINT,
  SPECIALIST_COMMON_TOOLS,
  SPECIALIST_PROFILES,
  buildWorkerTools,
  coordinatorPlannerPrompt,
  filterHandlersForSpecialist,
  proofToolHandlerNames,
  summarizeGuardianVerifyOutcome,
  verifierRepairFeedback,
  withVerifierRepairFeedback,
  workerSessionInstructions,
} from '../src/server/agent-session.ts'
import type { WorkerToolHandlers } from '../src/server/agent-session.ts'
import { buildAssignmentBrief } from '../src/server/assignment-brief.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { agentProofAttribution } from '../src/server/exec-verify.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { buildAgentScriptReceipt, verifyReceipt, type ScriptProofExchange } from '../src/server/proof-receipt.ts'
import {
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_TOKEN_NAME,
  VerifyRpcServer,
  createLocalAttemptFactory,
  prepareVerifyScript,
  verifyScript,
} from '../src/server/verify-rpc.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'
const SDK_DIR = join(dirname(fileURLToPath(import.meta.url)), '../worker/guardian_verify')

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

async function startBoundaryFixture(): Promise<{ origin: string; grant: Grant; close: () => Promise<void> }> {
  const server = createServer((req, res) => {
    const auth = req.headers.authorization ?? ''
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    res.setHeader('content-type', 'application/json')
    if (url.pathname === '/api/v1/items/1' && req.method === 'GET') {
      if (auth === 'Bearer tok-user-a') {
        res.statusCode = 200
        res.end(JSON.stringify({
          id: 'item-1',
          owner_id: 'owner-acme',
          tenant_id: 'acme',
          email: 'owner@acme.example',
          secretNote: 'private-acme-record-001',
        }))
        return
      }
      res.statusCode = 403
      res.end(JSON.stringify({ error: 'forbidden' }))
      return
    }
    res.statusCode = 404
    res.end(JSON.stringify({ error: 'not found' }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as { port: number }).port
  const origin = `http://127.0.0.1:${port}`
  const persona = (handle: string, roleLabel: string, secret: string): ResolvedPersona => ({
    id: `persona-${handle}`,
    handle,
    roleLabel,
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: 'Authorization',
    secret,
    canaryMarkers: [],
  })
  const personas = new Map<string, ResolvedPersona>([
    ['user_a', persona('user_a', 'member (beta)', 'tok-user-a')],
    ['user_b', persona('user_b', 'viewer (beta)', 'tok-user-b')],
  ])
  const grant = makeLabGrant(origin, { tier: 2, personas })
  return {
    origin,
    grant,
    close: async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

test('inline TS guardian_verify scripts execute and confirm for bare ctx body, export default, and explicit import styles', async t => {
  const fixture = await startBoundaryFixture()
  t.after(() => fixture.close())
  const makeFactory = () => createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions() {
      return {
        broker: new RequestBroker({ rejectUnauthorized: false }),
        grant: fixture.grant,
        runId: `run-inline-ts-${randomUUID().slice(0, 8)}`,
        assignmentId: 'assignment-inline-ts',
        targetOrigins: [fixture.origin],
      }
    },
  })

  // Tool description includes a concise working inline TS example matching the wrapper contract.
  assert.match(GUARDIAN_VERIFY_TOOL_DESCRIPTION, /ctx\.prove_access_boundary/)
  assert.match(GUARDIAN_VERIFY_TOOL_DESCRIPTION, /return ctx\.result\(/)

  // 1. Bare inline TS body (no imports, no export default, no runVerification)
  const bareVerdict = await verifyScript({
    candidate: {
      name: 'bare.ts',
      runtime: 'ts',
      code: `
const proof = await ctx.prove_access_boundary({
  controlPersona: 'user_b',
  probePersona: 'user_a',
  route: '/api/v1/items/1',
})
return ctx.result({ title: 'Cross-tenant item read (CWE-639)', severity: 'high' })
`,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(bareVerdict.confirmed, true, `${bareVerdict.reason}: ${bareVerdict.detail} | stderr=${bareVerdict.stderrPreview ?? ''}`)
  assert.equal(bareVerdict.attempts.length, 2)
  assert.equal(bareVerdict.attempts[0]!.oraclePassed, true)
  assert.equal(bareVerdict.attempts[1]!.oraclePassed, true)

  // 2. Bare inline TS body with snake_case keys and omitted return ctx.result(...)
  const bareNoReturnVerdict = await verifyScript({
    candidate: {
      name: 'bare-no-return.ts',
      runtime: 'ts',
      title: 'Cross-tenant item read auto-result',
      code: `
await ctx.prove_access_boundary({
  control_persona: 'user_b',
  probe_persona: 'user_a',
  route: '/api/v1/items/1',
})
`,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(bareNoReturnVerdict.confirmed, true, `${bareNoReturnVerdict.reason}: ${bareNoReturnVerdict.detail}`)
  assert.equal(bareNoReturnVerdict.claimTitle, 'Cross-tenant item read auto-result')

  // 3. `export default async (ctx) => { ... }` style (previously exited 0 with claims_missing)
  const exportDefaultVerdict = await verifyScript({
    candidate: {
      name: 'export-default.ts',
      runtime: 'ts',
      code: `
export default async (ctx) => {
  await ctx.prove_access_boundary({
    controlPersona: 'user_b',
    probePersona: 'user_a',
    route: '/api/v1/items/1',
  })
  return ctx.result({ title: 'Export default cross-tenant read (CWE-639)', severity: 'high' })
}
`,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(exportDefaultVerdict.confirmed, true, `${exportDefaultVerdict.reason}: ${exportDefaultVerdict.detail}`)
  assert.equal(exportDefaultVerdict.attempts[0]!.claimCount, 1)

  // 4. Explicit import (even extensionless `'guardian_verify'`) + `export default defineVerification(...)`
  const importExportVerdict = await verifyScript({
    candidate: {
      name: 'import-export.ts',
      runtime: 'ts',
      code: `
import { defineVerification } from 'guardian_verify'

export default defineVerification({
  async verify(ctx) {
    await ctx.prove_access_boundary({
      controlPersona: 'user_b',
      probePersona: 'user_a',
      route: '/api/v1/items/1',
    })
    return ctx.result({ title: 'Import/export defineVerification read (CWE-639)', severity: 'high' })
  },
})
`,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(importExportVerdict.confirmed, true, `${importExportVerdict.reason}: ${importExportVerdict.detail}`)

  // 5. Python bare inline script parity
  const pyBareVerdict = await verifyScript({
    candidate: {
      name: 'bare.py',
      runtime: 'python',
      title: 'Python bare inline BOLA read',
      code: `
ctx.prove_access_boundary('user_b', 'user_a', '/api/v1/items/1')
`,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(pyBareVerdict.confirmed, true, `${pyBareVerdict.reason}: ${pyBareVerdict.detail}`)

  // 6. prepareVerifyScript is idempotent across styles
  const onceWrapped = prepareVerifyScript(`await ctx.prove_access_boundary({ controlPersona: 'user_b', probePersona: 'user_a', route: '/api/v1/items/1' })`, 'ts')
  assert.equal(prepareVerifyScript(onceWrapped, 'ts'), onceWrapped)
})

test('failing and zero-claim inline TS scripts fail closed and surface bounded, redacted exitCode + stderrPreview + usageHint', async t => {
  const fixture = await startBoundaryFixture()
  t.after(() => fixture.close())
  const makeFactory = () => createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions() {
      return {
        broker: new RequestBroker({ rejectUnauthorized: false }),
        grant: fixture.grant,
        runId: `run-inline-fail-${randomUUID().slice(0, 8)}`,
        assignmentId: 'assignment-inline-fail',
        targetOrigins: [fixture.origin],
      }
    },
  })

  // 1. Runtime error containing a secret-like token must be redacted and bounded to <= 400 chars
  const leakedToken = 'Bearer super_secret_inline_token_987654321'
  const noisyTail = 'X'.repeat(600)
  const runtimeFailVerdict = await verifyScript({
    candidate: {
      name: 'runtime-fail.ts',
      runtime: 'ts',
      code: `
await ctx.http('/api/v1/items/1', { as: 'user_a' })
throw new Error('custom_probe_boom ${leakedToken} ${noisyTail}')
`,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(runtimeFailVerdict.confirmed, false)
  assert.equal(runtimeFailVerdict.reason, 'claims_missing')
  assert.equal(runtimeFailVerdict.exitCode, 1)
  assert.ok(runtimeFailVerdict.stderrPreview && runtimeFailVerdict.stderrPreview.includes('custom_probe_boom'))
  assert.ok(runtimeFailVerdict.stderrPreview.length <= 400, `stderrPreview must be <= 400 chars, got ${runtimeFailVerdict.stderrPreview.length}`)
  assert.equal(runtimeFailVerdict.stderrPreview.includes('super_secret_inline_token_987654321'), false, 'stderrPreview must redact Bearer tokens')
  assert.match(runtimeFailVerdict.stderrPreview, /\[redacted\]/)
  assert.equal(runtimeFailVerdict.usageHint, GUARDIAN_VERIFY_USAGE_HINT)

  // Summarization preserves exitCode, stderrPreview, and usageHint idempotently across double-summary
  const summary1 = summarizeGuardianVerifyOutcome(runtimeFailVerdict)
  const summary2 = summarizeGuardianVerifyOutcome(summary1)
  for (const summary of [summary1, summary2]) {
    assert.equal(summary.confirmed, false)
    assert.equal(summary.exitCode, 1)
    assert.ok(summary.stderrPreview && summary.stderrPreview.includes('custom_probe_boom'))
    assert.equal(summary.stderrPreview.includes('super_secret_inline_token_987654321'), false)
    assert.ok(summary.stderrPreview.length <= 400)
    assert.equal(summary.usageHint, GUARDIAN_VERIFY_USAGE_HINT)
  }

  // 2. Zero-claim script (makes an HTTP call but records no claims) still fails closed
  const zeroClaimsVerdict = await verifyScript({
    candidate: {
      name: 'zero-claims.ts',
      runtime: 'ts',
      code: `
await ctx.http('/api/v1/items/1', { as: 'user_a' })
console.log('confirmed: true')
`,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(zeroClaimsVerdict.confirmed, false)
  assert.equal(zeroClaimsVerdict.reason, 'claims_missing')
  assert.ok(zeroClaimsVerdict.usageHint, 'zero-claim failure must surface usageHint')

  // 3. Syntax error surfaces non-zero exitCode + stderrPreview through guardian_verify tool output
  const syntaxFailVerdict = await verifyScript({
    candidate: {
      name: 'syntax-fail.ts',
      runtime: 'ts',
      code: `await ctx.prove_access_boundary({ unclosed: `,
    },
    openAttempt: makeFactory(),
  })
  assert.equal(syntaxFailVerdict.confirmed, false)
  assert.equal(syntaxFailVerdict.reason, 'claims_missing')
  assert.notEqual(syntaxFailVerdict.exitCode, 0)
  assert.ok(syntaxFailVerdict.stderrPreview && syntaxFailVerdict.stderrPreview.length > 0 && syntaxFailVerdict.stderrPreview.length <= 400)

  const tools = buildWorkerTools({
    guardian_verify: async () => syntaxFailVerdict,
  }, v => v, AbortSignal.timeout(5_000), 64 * 1024, () => {})
  const gvTool = tools.find(tool => tool.name === 'guardian_verify')!
  const toolOut = await gvTool.execute(
    { script: 'await ctx.prove_access_boundary({ unclosed: ' } as never,
    {} as never,
    { abortSignal: AbortSignal.timeout(5_000) } as never,
  ) as { output: Array<{ text?: string }> }
  const payload = JSON.parse(toolOut.output[0]?.text ?? '{}') as {
    confirmed: boolean
    exitCode?: number
    stderrPreview?: string
    usageHint?: string
  }
  assert.equal(payload.confirmed, false)
  assert.notEqual(payload.exitCode, 0)
  assert.ok(payload.stderrPreview && payload.stderrPreview.length > 0 && payload.stderrPreview.length <= 400)
  assert.equal(payload.usageHint, GUARDIAN_VERIFY_USAGE_HINT)
})

test('VerifyRpcServer stages hostDir, token, context.json, and verify.sock with container-UID-accessible modes even under umask 0077', async t => {
  const fixture = await startBoundaryFixture()
  t.after(() => fixture.close())
  const previousUmask = process.umask(0o077)
  const server = new VerifyRpcServer({
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant: fixture.grant,
    runId: `run-umask-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assignment-umask',
    targetOrigins: [fixture.origin],
  })
  t.after(async () => {
    process.umask(previousUmask)
    await server.close()
  })
  await server.start()
  const dirMode = statSync(server.hostDir).mode & 0o777
  const contextMode = statSync(join(server.hostDir, VERIFY_RPC_CONTEXT_NAME)).mode & 0o777
  const tokenMode = statSync(join(server.hostDir, VERIFY_RPC_TOKEN_NAME)).mode & 0o777
  const socketMode = statSync(server.socketPath).mode & 0o777
  assert.ok((dirMode & 0o001) !== 0, `RPC hostDir must be traversable by container UID 10001 (got 0${dirMode.toString(8)})`)
  assert.ok((contextMode & 0o004) !== 0, `context.json must be world-readable for container UID 10001 (got 0${contextMode.toString(8)})`)
  assert.ok((tokenMode & 0o004) !== 0, `token must be world-readable for container UID 10001 (got 0${tokenMode.toString(8)})`)
  assert.equal(socketMode & 0o006, 0o006, `verify.sock must be connectable by container UID 10001 (got 0${socketMode.toString(8)})`)
})

test('TS wrapper edge cases (markdown fences, inline semicolon export default, standalone async fn) and Python await parity', async t => {
  const fixture = await startBoundaryFixture()
  t.after(() => fixture.close())
  const makeFactory = () => createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions() {
      return {
        broker: new RequestBroker({ rejectUnauthorized: false }),
        grant: fixture.grant,
        runId: `run-edge-${randomUUID().slice(0, 8)}`,
        assignmentId: 'assignment-edge',
        targetOrigins: [fixture.origin],
      }
    },
  })

  assert.match(GUARDIAN_VERIFY_TOOL_DESCRIPTION, /Python.*synchronous/i)
  assert.match(GUARDIAN_VERIFY_USAGE_HINT, /Python.*synchronous/i)

  // 1. Markdown-fenced TS script
  const fencedVerdict = await verifyScript({
    candidate: {
      name: 'fenced.ts',
      runtime: 'ts',
      code: [
        '```ts',
        "await ctx.prove_access_boundary({ controlPersona: 'user_b', probePersona: 'user_a', route: '/api/v1/items/1' })",
        "return ctx.result({ title: 'Fenced TS BOLA read (CWE-639)' })",
        '```',
      ].join('\n'),
    },
    openAttempt: makeFactory(),
  })
  assert.equal(fencedVerdict.confirmed, true, `${fencedVerdict.reason}: ${fencedVerdict.detail}`)

  // 2. Single-line statement followed by `; export default async (ctx) => ...`
  const inlineExportVerdict = await verifyScript({
    candidate: {
      name: 'inline-export.ts',
      runtime: 'ts',
      code: "const route = '/api/v1/items/1'; export default async (ctx) => { await ctx.prove_access_boundary({ controlPersona: 'user_b', probePersona: 'user_a', route }); return ctx.result({ title: 'Inline export default read (CWE-639)' }) }",
    },
    openAttempt: makeFactory(),
  })
  assert.equal(inlineExportVerdict.confirmed, true, `${inlineExportVerdict.reason}: ${inlineExportVerdict.detail}`)

  // 3. Standalone `async (ctx) => { ... }` and `async function(ctx) { ... }` without `export default`
  const standaloneFnVerdict = await verifyScript({
    candidate: {
      name: 'standalone-fn.ts',
      runtime: 'ts',
      code: "async function(ctx) { await ctx.prove_access_boundary({ controlPersona: 'user_b', probePersona: 'user_a', route: '/api/v1/items/1' }); return ctx.result({ title: 'Standalone async fn read (CWE-639)' }) }",
    },
    openAttempt: makeFactory(),
  })
  assert.equal(standaloneFnVerdict.confirmed, true, `${standaloneFnVerdict.reason}: ${standaloneFnVerdict.detail}`)

  // 4. Python inline script using `await ctx.prove_access_boundary(...)` (bare body + async def)
  const pyAwaitBareVerdict = await verifyScript({
    candidate: {
      name: 'py-await-bare.py',
      runtime: 'python',
      title: 'Python await bare BOLA read',
      code: "proof = await ctx.prove_access_boundary('user_b', 'user_a', '/api/v1/items/1')\nreturn ctx.result('Python await bare BOLA read')",
    },
    openAttempt: makeFactory(),
  })
  assert.equal(pyAwaitBareVerdict.confirmed, true, `${pyAwaitBareVerdict.reason}: ${pyAwaitBareVerdict.detail} | stderr=${pyAwaitBareVerdict.stderrPreview ?? ''}`)

  const pyAsyncDefVerdict = await verifyScript({
    candidate: {
      name: 'py-async-def.py',
      runtime: 'python',
      code: "async def verify(ctx):\n    ex = await ctx.http('/api/v1/items/1', as_persona='user_a')\n    await ctx.prove_access_boundary('user_b', 'user_a', '/api/v1/items/1')\n    return ctx.result('Python async def BOLA read')",
    },
    openAttempt: makeFactory(),
  })
  assert.equal(pyAsyncDefVerdict.confirmed, true, `${pyAsyncDefVerdict.reason}: ${pyAsyncDefVerdict.detail} | stderr=${pyAsyncDefVerdict.stderrPreview ?? ''}`)
})

test('guardian_verify tool accepts code/source aliases, returns 1-line JSON example on missing script, and flags repeated validation loops', async () => {
  const receivedScripts: string[] = []
  const handlers: WorkerToolHandlers = {
    guardian_verify: async args => {
      receivedScripts.push(args.script ?? '')
      return { confirmed: false, reason: 'oracle_failed', detail: 'stub' }
    },
    record_fact: async () => ({}),
    record_coverage: async () => ({}),
    complete_intent: async () => ({}),
  }
  const tools = buildWorkerTools(handlers, v => v, AbortSignal.timeout(5_000), 64 * 1024, () => {})
  const gvTool = tools.find(tool => tool.name === 'guardian_verify')
  assert.ok(gvTool, 'guardian_verify tool must be built')

  const execCtx = { abortSignal: new AbortController().signal } as Parameters<typeof gvTool.execute>[2]
  const dummyApi = {} as Parameters<typeof gvTool.execute>[1]

  // 1. `code` alias normalizes to `script`
  const viaCode = await gvTool.execute({ code: "await ctx.prove_access_boundary({ route: '/api/a' })", runtime: 'ts' }, dummyApi, execCtx)
  assert.equal(viaCode.isError ?? false, false)
  assert.equal(receivedScripts[0], "await ctx.prove_access_boundary({ route: '/api/a' })")

  // 2. `source` alias normalizes to `script`
  const viaSource = await gvTool.execute({ source: "await ctx.prove_access_boundary({ route: '/api/b' })", runtime: 'ts' }, dummyApi, execCtx)
  assert.equal(viaSource.isError ?? false, false)
  assert.equal(receivedScripts[1], "await ctx.prove_access_boundary({ route: '/api/b' })")

  // 3. Missing script returns actionable 1-line JSON call example and triggers loop-stop guidance on 3rd failure
  const err1 = await gvTool.execute({ runtime: 'ts' }, dummyApi, execCtx)
  assert.equal(err1.isError, true)
  const text1 = (err1.output ?? []).map(o => ('text' in o ? o.text : '')).join('')
  assert.match(text1, /Example call: \{"script":/)
  assert.equal(text1.includes('stop retrying malformed calls'), false)

  await gvTool.execute({ runtime: 'ts' }, dummyApi, execCtx)
  const err3 = await gvTool.execute({ runtime: 'ts' }, dummyApi, execCtx)
  assert.equal(err3.isError, true)
  const text3 = (err3.output ?? []).map(o => ('text' in o ? o.text : '')).join('')
  assert.match(text3, /stop retrying malformed calls/)
})

test('planner prompt and worker assignment brief explicitly mark floor-confirmed routes as DO NOT RE-PROVE without 10-item truncation', () => {
  const confirmed = Array.from({ length: 14 }, (_, i) => ({
    origin: 'http://127.0.0.1:4101',
    method: 'GET',
    path: `/api/v1/resource-${i + 1}/:id`,
    cwe: 'CWE-639',
    probeClass: 'broken-access-control',
  }))

  const plannerJson = JSON.parse(coordinatorPlannerPrompt({
    goal: 'Test unconfirmed routes',
    roundNo: 1,
    capabilityTier: 2,
    approvedOrigins: ['http://127.0.0.1:4101'],
    budgetRemaining: { usd: 2, requests: 'unlimited' },
    dynamicStepBudget: 12,
    pendingOob: 0,
    chainSteps: [],
    alreadyConfirmed: confirmed,
  })) as { alreadyConfirmedByFloor?: { directive: string; items: Array<{ path: string }> } }

  assert.ok(plannerJson.alreadyConfirmedByFloor)
  assert.match(plannerJson.alreadyConfirmedByFloor.directive, /ALREADY CONFIRMED BY FLOOR — DO NOT RE-PROVE/)
  assert.equal(plannerJson.alreadyConfirmedByFloor.items.length, 14, 'must not truncate 14 floor hits at 10')

  const brief = JSON.parse(buildAssignmentBrief({
    missionKind: 'class_scan',
    origin: 'http://127.0.0.1:4101',
    routes: [{ method: 'POST', path: '/api/v1/unconfirmed-action', riskScore: 85 }],
    alreadyConfirmedOnOrigin: confirmed.slice(0, 4),
  })) as { alreadyConfirmedDirective?: string; alreadyConfirmedOnOrigin?: unknown[] }
  assert.match(brief.alreadyConfirmedDirective ?? '', /ALREADY CONFIRMED BY FLOOR — DO NOT RE-PROVE/)
  assert.equal(brief.alreadyConfirmedOnOrigin?.length, 4)
})
