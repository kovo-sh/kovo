/**
 * v5.1 agentic-tools stream: typed proof tool registration, repairable validation errors,
 * structured verifier feedback, opt-in trace events, and N-2 settlement wording.
 *
 * Fixtures are synthetic: no benchmark/app/route/seed literals, no external network.
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { randomUUID } from 'node:crypto'
import type { AgentTrace } from '../src/server/agent-trace.ts'
import { createAgentTrace, readTrace, SecretRegistry } from '../src/server/agent-trace.ts'
import {
  AGENTIC_SPECIALIST_MAX_TURNS,
  SPECIALIST_PROFILES,
  buildWorkerTools,
  capabilityBundlesFor,
  investigatorTools,
  proofToolHandlerNames,
  settlementDue,
  settlementNudgeMessage,
  settlementNudgeTurnFor,
  verifierRepairFeedback,
  withVerifierRepairFeedback,
  runAgentSession,
} from '../src/server/agent-session.ts'
import type { CompiledProof, ProofToolName } from '../src/server/proof-tools.ts'
import { describeProofTools } from '../src/server/proof-tools.ts'

const origin = 'https://app.example.invalid'

function tempDir(t: { after: (fn: () => void) => void }, prefix = 'guardian-v5-agentic-tools-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function toolByName(tools: ReturnType<typeof buildWorkerTools>, name: string) {
  return tools.find(tool => tool.name === name)
}

function textOf(result: { output?: readonly { type: string; text?: string }[] }): string {
  return (result.output ?? [])
    .filter(part => part.type === 'text')
    .map(part => part.text ?? '')
    .join('\n')
}

const validAuthzInput = {
  origin,
  ownerPersona: 'user_a',
  attackerPersona: 'user_b',
  endpoint: '/api/orders/{resourceId}',
  resourceId: 'order-1234',
  identifierPath: 'id',
}

async function invoke(tool: NonNullable<ReturnType<typeof toolByName>>, args: Record<string, unknown>) {
  return tool.execute(
    args as never,
    {} as never,
    { abortSignal: AbortSignal.timeout(5_000) } as never,
  ) as Promise<{ output?: readonly { type: string; text?: string }[]; isError?: boolean }>
}

// ============================================================================
// 1. Tool list: typed proof tools are opt-in per handler
// ============================================================================

test('proof tools are absent without handlers and present for exactly the supplied handlers', () => {
  const withoutProofs = buildWorkerTools(
    { complete_intent: async () => ({ ok: true }) },
    value => value,
    AbortSignal.timeout(5_000),
    24 * 1024,
    () => {},
  )
  for (const name of proofToolHandlerNames) assert.equal(toolByName(withoutProofs, name), undefined)
  assert.ok(toolByName(withoutProofs, 'complete_intent'), 'complete_intent stays available')

  const handlers = {
    prove_authz_read_diff: async () => ({ ok: true }),
    prove_business_invariant: async () => ({ ok: true }),
  }
  const withProofs = buildWorkerTools(
    { ...handlers, complete_intent: async () => ({ ok: true }) },
    value => value,
    AbortSignal.timeout(5_000),
    24 * 1024,
    () => {},
  )
  assert.ok(toolByName(withProofs, 'prove_authz_read_diff'))
  assert.ok(toolByName(withProofs, 'prove_business_invariant'))
  assert.equal(toolByName(withProofs, 'prove_state_mutation_diff'), undefined)
  assert.equal(toolByName(withProofs, 'prove_canary_or_redirect'), undefined)
})

test('proof tool names, required fields and one-line usage mirror describeProofTools', () => {
  const handlers = Object.fromEntries(proofToolHandlerNames.map(name => [name, async () => ({ ok: true })]))
  const tools = buildWorkerTools(
    handlers,
    value => value,
    AbortSignal.timeout(5_000),
    24 * 1024,
    () => {},
  )
  const described = describeProofTools()
  for (const name of proofToolHandlerNames) {
    const tool = toolByName(tools, name)
    assert.ok(tool, `${name} must be registered`)
    const schema = tool.parameters as unknown as { required?: string[] }
    const expected = described.find(entry => entry.name === name)!
    assert.deepEqual(schema.required, [...expected.inputSchema.required], `${name} required fields`)
    assert.ok(tool.description.startsWith(expected.usage), `${name} exposes its one-line usage`)
    assert.match(tool.description, /ok: false, errors/)
  }
})

test('legacy raw-spec submission tools are never removed', () => {
  const tools = buildWorkerTools(
    { propose_chain_finding: async () => ({ ok: true }), verify_replay_spec: async () => ({ ok: true }) },
    value => value,
    AbortSignal.timeout(5_000),
    24 * 1024,
    () => {},
  )
  assert.ok(toolByName(tools, 'propose_chain_finding'))
  assert.ok(toolByName(tools, 'verify_replay_spec'))
})

test('proof tools join the base bundle without re-expanding the slim skill catalog', () => {
  // v6 fluid bundles replaced the per-profile `allowedTools` allowlist (plans/better-architecture.md
  // §3.3), so the typed-proof guarantee is asserted through the resolved bundle instead.
  for (const [id, profile] of Object.entries(SPECIALIST_PROFILES)) {
    const tools = investigatorTools(capabilityBundlesFor('', profile.capabilities))
    assert.ok(tools.includes('prove_authz_read_diff'), `${id} must allow typed proofs through the base bundle`)
    assert.ok(profile.skills.length >= 2 && profile.skills.length < 10, `${id} keeps a slim skill list`)
    assert.equal(new Set(profile.skills).size, profile.skills.length, `${id} has no duplicate skills`)
    assert.equal(new Set(tools).size, tools.length, `${id} has no duplicate bundle tool entries`)
  }
})

// ============================================================================
// 2. Validation errors are structured and never reach the handler
// ============================================================================

test('invalid proof input returns { ok:false, errors[] } and does not call the handler', async () => {
  let calls = 0
  const tools = buildWorkerTools(
    {
      prove_authz_read_diff: async () => {
        calls += 1
        return { ok: true }
      },
    },
    value => value,
    AbortSignal.timeout(5_000),
    24 * 1024,
    () => {},
  )
  const tool = toolByName(tools, 'prove_authz_read_diff')!
  const result = await invoke(tool, {
    ...validAuthzInput,
    attackerPersona: 'user_a',
  })
  assert.equal(calls, 0, 'handler must not run on validation failure')
  const parsed = JSON.parse(textOf(result)) as {
    ok: boolean
    errors: Array<{ field: string; code: string; message: string; fix: string }>
  }
  assert.equal(parsed.ok, false)
  assert.ok(parsed.errors.length > 0)
  for (const issue of parsed.errors) {
    assert.equal(typeof issue.field, 'string')
    assert.equal(typeof issue.code, 'string')
    assert.ok(issue.message)
    assert.ok(issue.fix)
  }
  assert.ok(parsed.errors.some(issue => issue.field === 'attackerPersona'), 'conflicting roles is repairable in one turn')
})

test('a valid proof forwards the compiled spec to the handler and returns its outcome', async () => {
  let received: CompiledProof | undefined
  const tools = buildWorkerTools(
    {
      prove_authz_read_diff: async (proof) => {
        received = proof
        return { ok: true, exchangeIds: ['ex-proof-1'], verdict: 'confirmed' }
      },
    },
    value => value,
    AbortSignal.timeout(5_000),
    24 * 1024,
    () => {},
  )
  const result = await invoke(toolByName(tools, 'prove_authz_read_diff')!, validAuthzInput)
  assert.ok(received, 'handler receives the compiled proof')
  assert.equal(received!.spec.kind, 'http_chain')
  assert.ok(received!.assertionsJq.length > 0)
  assert.equal(typeof received!.spaCatchallControl, 'boolean')
  assert.ok(received!.rationale.length > 0)
  assert.deepEqual(JSON.parse(textOf(result)), { ok: true, exchangeIds: ['ex-proof-1'], verdict: 'confirmed' })
})

// ============================================================================
// 3. Structured verifier repair feedback
// ============================================================================

test('failed verification surfaces bounded, repairable feedback while successes pass through', () => {
  const body = 'B'.repeat(900)
  const feedback = verifierRepairFeedback({
    verdict: 'inconclusive',
    failedStepId: 'probe',
    controlPassed: true,
    stepStatuses: [{ id: 'probe', role: 'probe', status: 200, bodyLen: 900 }],
    keyHeaders: { 'content-type': 'application/json' },
    bodyPreview: body,
    extractedVars: { orderId: 'order-1234' },
    jqError: 'observed is not a string',
  })
  assert.ok(feedback)
  assert.equal(feedback!.failedRule, 'step:probe')
  assert.equal(Buffer.byteLength(feedback!.bodyPreview ?? '', 'utf8') <= 512, true)
  assert.deepEqual(feedback!.stepStatuses, [{ id: 'probe', role: 'probe', status: 200, bodyLen: 900 }])
  assert.deepEqual(feedback!.extractedVars, { orderId: 'order-1234' })
  assert.match(feedback!.suggestedFix ?? '', /assertionsJq/)

  const wrapped = withVerifierRepairFeedback({ verdict: 'dismissed', controlPassed: false }) as Record<string, unknown>
  assert.ok(wrapped.repair, 'failure outcomes gain a repair block')
  assert.equal(verifierRepairFeedback({ verdict: 'confirmed', controlPassed: true }), null)
  const success = { ok: true, exchangeIds: ['ex-1'] }
  assert.equal(withVerifierRepairFeedback(success), success, 'success outcomes are not rewritten')

  // Inline verification nests its feedback under inlineVerifyFeedback (Execution shape).
  const nested = withVerifierRepairFeedback({
    findingId: 'finding-1',
    status: 'pending',
    inlineVerifyFeedback: {
      verdict: 'inconclusive',
      controlPassed: false,
      jqError: 'could not parse jq output',
      stepStatuses: [{ id: 'control', role: 'control', status: 500, bodyLen: 0 }],
      retriesRemaining: 1,
    },
  }) as { repair?: { failedRule: string | null; suggestedFix: string } }
  assert.ok(nested.repair)
  assert.equal(nested.repair!.failedRule, 'verdict:inconclusive')
  assert.match(nested.repair!.suggestedFix, /assertionsJq/)
})

// ============================================================================
// 4. Settlement: N-2 nudge wording and wall-clock predicate
// ============================================================================

test('N-2 settlement nudge names typed proof tools and complete_intent', () => {
  const nudge = settlementNudgeMessage({ turn: 7, maxTurns: AGENTIC_SPECIALIST_MAX_TURNS, proofTools: proofToolHandlerNames })
  assert.match(nudge, /Turn 7\/9/)
  assert.match(nudge, /N-2/)
  for (const name of proofToolHandlerNames) assert.ok(nudge.includes(name), `${name} must be offered`)
  assert.match(nudge, /propose_chain_finding/)
  assert.match(nudge, /complete_intent/)
  assert.equal(settlementNudgeTurnFor(AGENTIC_SPECIALIST_MAX_TURNS), 7)
})

test('settlementDue honors the turn threshold, external trigger, and wall-clock deadline', () => {
  const base = { turnsUsed: 0, settlementTurn: 5, settled: false }
  assert.equal(settlementDue(base), false)
  assert.equal(settlementDue({ ...base, turnsUsed: 5 }), true)
  assert.equal(settlementDue({ ...base, settled: true }), true)
  assert.equal(settlementDue({ ...base, shouldSettle: () => true }), true)
  assert.equal(settlementDue({ ...base, shouldSettle: () => { throw new Error('boom') } }), false, 'a throwing trigger must not break the run')
  assert.equal(settlementDue({ ...base, wallClockDeadline: 1_000, now: () => 1_000 }), true)
  assert.equal(settlementDue({ ...base, wallClockDeadline: 1_000, now: () => 999 }), false)
})

// ============================================================================
// 5. Trace: opt-in, redacted turn + tool_result events
// ============================================================================

interface FixtureResponse {
  text?: string
  toolCalls?: Array<{ name: string; args: Record<string, unknown> }>
}

function sseResponsesPayload(response: FixtureResponse): string {
  const responseId = 'resp_' + randomUUID().slice(0, 12)
  const events: Record<string, unknown>[] = [
    { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } },
  ]
  const output: Record<string, unknown>[] = []
  let idx = 0
  if (response.text) {
    const msgId = 'msg_' + randomUUID().slice(0, 8)
    events.push(
      { type: 'response.output_item.added', output_index: idx, item: { id: msgId, type: 'message', status: 'in_progress', role: 'assistant', content: [] } },
      { type: 'response.output_text.delta', output_index: idx, item_id: msgId, content_index: 0, delta: response.text },
      { type: 'response.output_text.done', output_index: idx, item_id: msgId, content_index: 0, text: response.text },
      { type: 'response.output_item.done', output_index: idx, item: { id: msgId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text: response.text }] } },
    )
    output.push({ id: msgId, type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: response.text }] })
    idx += 1
  }
  for (const call of response.toolCalls ?? []) {
    const fcId = 'fc_' + randomUUID().slice(0, 8)
    const callId = 'call_' + randomUUID().slice(0, 8)
    const serialized = JSON.stringify(call.args)
    events.push(
      { type: 'response.output_item.added', output_index: idx, item: { id: fcId, type: 'function_call', status: 'in_progress', call_id: callId, name: call.name, arguments: '' } },
      { type: 'response.function_call_arguments.delta', output_index: idx, item_id: fcId, delta: serialized },
      { type: 'response.function_call_arguments.done', output_index: idx, item_id: fcId, name: call.name, arguments: serialized },
      { type: 'response.output_item.done', output_index: idx, item: { id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: call.name, arguments: serialized } },
    )
    output.push({ id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: call.name, arguments: serialized })
    idx += 1
  }
  events.push({
    type: 'response.completed',
    response: {
      id: responseId,
      status: 'completed',
      output,
      usage: { input_tokens: 120, output_tokens: 40, total_tokens: 160 },
    },
  })
  return events.map(event => `data: ${JSON.stringify(event)}\n\n`).join('') + 'data: [DONE]\n\n'
}

async function fixtureServer(
  respond: (body: Record<string, unknown>, index: number) => FixtureResponse,
) {
  const bodies: Array<Record<string, unknown>> = []
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = []
    for await (const chunk of req) chunks.push(Buffer.from(chunk))
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>
    bodies.push(body)
    res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(sseResponsesPayload(respond(body, bodies.length - 1)))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fixture has no address')
  return {
    url: `http://127.0.0.1:${address.port}`,
    bodies,
    close: () => new Promise<void>(resolve => server.close(() => resolve())),
  }
}

test('trace is off by default and a throwing trace never breaks the run', async (t) => {
  const dir = tempDir(t)
  const server = await fixtureServer(() => ({ text: 'no-trace-ok' }))
  t.after(() => server.close())

  const result = await runAgentSession({
    directory: dir,
    sessionId: 'no-trace',
    requestId: randomUUID(),
    settings: { endpoint: server.url, model: 'fixture-1', protocol: 'responses', key: 'fixture-key-1234' },
    scenario: 'worker-investigation',
    prompt: 'summarize',
    signal: AbortSignal.timeout(15_000),
    maxTurns: 1,
    enableSettlement: false,
    requireCompleteIntent: false,
  })
  assert.equal(result.answer, 'no-trace-ok')

  const throwingTrace = {
    enabled: true,
    dir: join(dir, 'never-written'),
    recordTurn: () => { throw new Error('trace turned') },
    recordToolResult: () => { throw new Error('trace tool result') },
    recordPlannerDecision: () => { throw new Error('trace planner') },
    recordLifecycle: () => { throw new Error('trace lifecycle') },
    traceSize: () => { throw new Error('trace size') },
    closeTrace: () => { throw new Error('trace close') },
  } as unknown as AgentTrace

  const throwing = await runAgentSession({
    directory: dir,
    sessionId: 'throwing-trace',
    requestId: randomUUID(),
    settings: { endpoint: server.url, model: 'fixture-1', protocol: 'responses', key: 'fixture-key-1234' },
    scenario: 'worker-investigation',
    prompt: 'summarize',
    signal: AbortSignal.timeout(15_000),
    maxTurns: 1,
    enableSettlement: false,
    requireCompleteIntent: false,
    trace: throwingTrace,
  })
  assert.equal(throwing.answer, 'no-trace-ok', 'trace failures must not change the answer')
})

test('trace records a turn and a redacted tool_result with verifier feedback and ids', async (t) => {
  const dir = tempDir(t)
  const traceDir = join(dir, 'trace')
  const secret = 'TRACE_SECRET_7f6e5d4c3b2a'
  const registry = new SecretRegistry()
  registry.register('canary', 'fixture', secret)
  const trace = createAgentTrace({
    dir: traceDir,
    secrets: registry,
    manifest: { gitSha: 'test-sha', app: 'unit-app', seed: 42, mode: 'agentic', model: 'fixture-1' },
  })

  const server = await fixtureServer((_body, index) => index === 0
    ? {
        toolCalls: [{
          name: 'record_fact',
          args: { kind: 'note', origin, summary: `observed ${secret}` },
        }],
      }
    : { text: 'trace-run-done' })
  t.after(() => server.close())

  const result = await runAgentSession({
    directory: dir,
    sessionId: 'trace-test',
    requestId: 'req-trace',
    settings: { endpoint: server.url, model: 'fixture-1', protocol: 'responses', key: 'fixture-key-1234' },
    scenario: 'worker-investigation',
    prompt: 'record a note',
    signal: AbortSignal.timeout(15_000),
    maxTurns: 2,
    enableSettlement: false,
    requireCompleteIntent: false,
    trace,
    traceContext: { runId: 'run-1', assignmentId: 'assignment-1', specialistProfile: 'probe-specialist' },
    handlers: {
      record_fact: async () => ({
        ok: true,
        exchangeIds: ['ex-1'],
        factIds: ['fact-1'],
        findingIds: ['finding-1'],
        verdict: 'dismissed',
        controlPassed: false,
        jqError: 'observed must be a string',
        stepStatuses: [{ id: 'probe', role: 'probe', status: 200, bodyLen: 12 }],
        bodyPreview: `body ${secret}`,
        serverSecret: secret,
      }),
    },
  })
  assert.equal(result.answer, 'trace-run-done')

  const eventsText = readFileSync(join(traceDir, 'events.jsonl'), 'utf8')
  assert.equal(eventsText.includes(secret), false, 'raw secrets must never reach the trace')

  const { events } = readTrace(traceDir)
  const turns = events.filter(event => event.type === 'turn')
  assert.ok(turns.length >= 1)
  const first = turns[0]
  assert.equal(first.type, 'turn')
  assert.equal(first.runId, 'run-1')
  assert.equal(first.assignmentId, 'assignment-1')
  assert.equal(first.specialistProfile, 'probe-specialist')
  assert.equal(first.model, 'fixture-1')
  assert.match(first.promptPrefixHash ?? '', /^[a-f0-9]{64}$/)
  assert.ok(first.deltaMessages, 'delta messages are recorded')
  assert.ok(first.outputTextHash)
  assert.equal(first.toolCalls[0]?.name, 'record_fact')
  assert.equal(first.toolCalls.length, 1)

  const toolResults = events.filter(event => event.type === 'tool_result')
  assert.equal(toolResults.length, 1)
  const toolResult = toolResults[0]
  assert.equal(toolResult.name, 'record_fact')
  assert.equal(toolResult.ok, true)
  assert.deepEqual(toolResult.exchangeIds, ['ex-1'])
  assert.deepEqual(toolResult.factIds, ['fact-1'])
  assert.deepEqual(toolResult.findingIds, ['finding-1'])
  assert.ok(toolResult.summaryJson?.inline, 'summary JSON is recorded')
  assert.ok(toolResult.verifierFeedback?.inline, 'verifier feedback is recorded')
  assert.match(toolResult.verifierFeedback!.inline!, /jqError|stepStatuses/)
  assert.equal(toolResult.verifierFeedback!.inline!.includes(secret), false)
})

// ============================================================================
// 6. N-2 nudge reaches the model exactly at N-2
// ============================================================================

test('the N-2 nudge is injected on turn N-2 and the 85% banner follows', async (t) => {
  const dir = tempDir(t)
  const server = await fixtureServer(() => ({
    toolCalls: [{
      name: 'record_fact',
      args: { kind: 'note', origin, summary: 'progress note' },
    }],
  }))
  t.after(() => server.close())

  const maxTurns = 6
  const proofHandler = async () => ({ ok: true })
  await runAgentSession({
    directory: dir,
    sessionId: 'settlement-nudge',
    requestId: randomUUID(),
    settings: { endpoint: server.url, model: 'fixture-1', protocol: 'responses', key: 'fixture-key-1234' },
    scenario: 'worker-investigation',
    prompt: 'keep probing',
    signal: AbortSignal.timeout(30_000),
    maxTurns,
    requireCompleteIntent: false,
    handlers: {
      record_fact: async () => ({ ok: true }),
      prove_authz_read_diff: proofHandler,
      complete_intent: async () => ({ ok: true }),
    },
  })

  const serialized = server.bodies.map(body => JSON.stringify(body))
  const nudgeTurn = settlementNudgeTurnFor(maxTurns)
  assert.equal(nudgeTurn, 4)
  const nudgeBody = serialized.find(body => body.includes('SETTLEMENT NUDGE'))
  assert.ok(nudgeBody, 'a settlement nudge must be injected')
  assert.ok(nudgeBody!.includes(`Turn ${nudgeTurn}/${maxTurns}`), 'nudge fires at N-2')
  assert.ok(nudgeBody!.includes('prove_authz_read_diff'), 'nudge offers the registered typed proof tool')
  assert.ok(nudgeBody!.includes('complete_intent'))

  const bannerBody = serialized.find(body => body.includes('SETTLEMENT NOTICE'))
  assert.ok(bannerBody, 'the 85% settlement banner still fires')
  assert.ok(bannerBody!.includes('prove_authz_read_diff'))
})

test('a proof tool name is only advertised in settlement text when its handler exists', () => {
  const message = settlementNudgeMessage({ turn: 4, maxTurns: 6 })
  assert.equal(message.includes('prove_authz_read_diff'), false)
  assert.match(message, /propose_chain_finding/)
})

// Keep the proof tool name union referenced so an accidental schema rename fails the typecheck.
const _proofNames: ProofToolName[] = [...proofToolHandlerNames]
assert.equal(_proofNames.length, 4)
