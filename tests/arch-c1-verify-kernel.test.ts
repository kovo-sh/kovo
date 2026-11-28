/**
 * Architecture Wave 3 Proposal C1 — Verification Stack Tightening & `agent-session.ts` Decomposition.
 *
 * Verifies (zero Docker, synthetic fixtures only):
 *  1. `src/server/agent-session.ts` stays <= 4,000 LOC (well below the 4,200 LOC ceiling) after
 *     extracting prompt/instruction/guidance builders into `src/server/agent-prompts.ts`.
 *  2. Full re-export identity parity between `agent-prompts.ts` and `agent-session.ts` (zero
 *     broken external imports), preserving `codeAuditPrompt`'s incremental `record_fact` policy
 *     and `v8-sdk-adoption`'s 4 KB brief cap & v8 multi-hop SDK helpers.
 *  3. Legacy `verify_replay_spec` is omitted from LLM tool schemas whenever `kovo_verify` is
 *     active (preventing LLM DSL dilution), while `allowLegacyReplaySpec: true` explicitly opts
 *     it back in and replay-only sessions without `kovo_verify` keep it available.
 *  4. `propose_chain_finding` trims retired/runtime DSL schemas from its tool description while
 *     `kovo_verify` is active, keeping `static_ast_proof` usable.
 *  5. `runAgentSession` never sends `verify_replay_spec` in the LLM tool definitions when
 *     `kovo_verify` is active.
 *  6. `replay-feedback.ts` short-circuits retired legacy DSL payloads cleanly with
 *     `retriesRemaining: 0` and redacted `assertionSummary`, with zero v8 contamination.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { once } from 'node:events'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import * as agentPrompts from '../src/server/agent-prompts.ts'
import * as agentSession from '../src/server/agent-session.ts'
import { buildAssignmentBriefPacket, ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE } from '../src/server/assignment-brief.ts'
import { buildInlineVerifyFeedback } from '../src/server/replay-feedback.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function loc(relPath: string): number {
  return readFileSync(join(REPO_ROOT, relPath), 'utf8').split('\n').length
}

test('C1.1: agent-session.ts is decomposed below 4,000 LOC (and <= 4,200 LOC ceiling) with agent-prompts.ts owning prompt builders', () => {
  const sessionLoc = loc('src/server/agent-session.ts')
  const promptsLoc = loc('src/server/agent-prompts.ts')
  assert.ok(sessionLoc <= 4200, `agent-session.ts is ${sessionLoc} LOC (must be <= 4,200)`)
  assert.ok(sessionLoc <= 4000, `agent-session.ts is ${sessionLoc} LOC (target <= 4,000)`)
  assert.ok(promptsLoc > 500, `agent-prompts.ts should own the extracted prompt/guidance builders (got ${promptsLoc} LOC)`)

  const sessionSource = readFileSync(join(REPO_ROOT, 'src/server/agent-session.ts'), 'utf8')
  const promptsSource = readFileSync(join(REPO_ROOT, 'src/server/agent-prompts.ts'), 'utf8')

  for (const decl of [
    'export function codeAuditPrompt(',
    'export function workerSessionInstructions(',
    'export function buildAgenticPromptContext(',
    'export function kovoVerifyHelperGuidance(',
    'export function kovoVerifyPromptHint(',
    'export const KOVO_VERIFY_MULTIHOP_HELPERS',
    'export const KOVO_VERIFY_TOOL_DESCRIPTION',
    'export const scenarioInstructions:',
  ]) {
    assert.ok(promptsSource.includes(decl), `agent-prompts.ts must own ${decl}`)
    assert.ok(!sessionSource.includes(decl), `agent-session.ts must not duplicate ${decl}`)
  }
})

test('C1.2: agent-session.ts maintains strict re-export identity parity with agent-prompts.ts and preserves v8 prompt contracts', () => {
  const sharedSymbols = [
    'codeAuditPrompt',
    'scenarioInstructions',
    'workerSessionInstructions',
    'KOVO_VERIFY_HELPERS',
    'KOVO_VERIFY_CLASS_HINTS',
    'KOVO_VERIFY_MULTIHOP_HELPERS',
    'KOVO_VERIFY_TOOL_DESCRIPTION',
    'KOVO_VERIFY_USAGE_HINT',
    'KOVO_VERIFY_REPAIR_INSTRUCTION',
    'KOVO_VERIFY_SPEC_SHAPE',
    'KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES',
    'kovoVerifyHelperGuidance',
    'kovoVerifyPromptHint',
    'kovoVerifyRedirectMessage',
    'buildAgenticPromptContext',
    'coordinatorPrompt',
    'threatModelPrompt',
    'chainPlannerPrompt',
    'patchAuthorPrompt',
    'patchReviewerPrompt',
    'workerInvestigationPrompt',
    'workerInput',
    'SPECIALIST_PROFILES',
    'SPECIALIST_COMMON_TOOLS',
    'filterHandlersForSpecialist',
    'routeStepToSpecialist',
    'summarizeKovoVerifyOutcome',
    'verifierRepairFeedback',
    'withVerifierRepairFeedback',
    'proposeChainFindingDescription',
  ] as const

  for (const name of sharedSymbols) {
    assert.ok(name in agentPrompts, `agent-prompts.ts missing ${name}`)
    assert.ok(name in agentSession, `agent-session.ts missing re-export ${name}`)
    assert.equal(
      (agentSession as Record<string, unknown>)[name],
      (agentPrompts as Record<string, unknown>)[name],
      `agent-session.ts must re-export ${name} directly from agent-prompts.ts`,
    )
  }

  // Incremental record_fact directive in codeAuditPrompt stays intact.
  const auditPrompt = agentSession.codeAuditPrompt({
    goal: 'Audit mounted repositories',
    capabilityTier: 2,
    approvedOrigins: ['https://app.example.invalid'],
    mountedRepos: ['demo-repo'],
  })
  const parsedAudit = JSON.parse(auditPrompt) as { recordingPolicy?: { mode?: string; rule?: string } }
  assert.equal(parsedAudit.recordingPolicy?.mode, 'incremental')
  assert.match(parsedAudit.recordingPolicy?.rule ?? '', /record_fact\(kind="code_audit_suspect"\)/)

  // Expanded 4 KB multi-hop brief preservation in buildAgenticPromptContext stays intact.
  const packet = buildAssignmentBriefPacket({
    missionKind: 'multihop_chain',
    origin: 'https://api.example.invalid',
    routes: [
      { method: 'GET', path: '/api/v1/hop1', riskScore: 80 },
      { method: 'POST', path: '/api/v1/target', riskScore: 95 },
    ],
    personas: [
      { handle: 'member_b', role: 'member (org_b)' },
      { handle: 'owner_a', role: 'owner (org_a)' },
    ],
    hopCheckpoint: {
      branchKey: 'branch-c1',
      depth: 2,
      verifiedHops: [{ hop: 1, receiptId: 'h1', capId: 'cap:hop_1:tok', surface: 'http', actor: 'member_b' }],
      capabilityHandles: ['cap:hop_1:tok'],
      nextGoal: { endpoint: 'POST /api/v1/target', goal: 'Pivot via cap:hop_1:tok' },
      doNotRediscover: true,
    },
  })
  assert.ok(packet.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
  const ctx = agentSession.buildAgenticPromptContext({ assignmentBrief: packet.text })
  assert.equal(ctx.evidenceBrief, packet.text)
})

test('C1.3: verify_replay_spec is hidden from tool schemas when kovo_verify is active (preventing LLM DSL dilution)', () => {
  const noop = async () => ({ ok: true })
  const handlers: agentSession.WorkerToolHandlers = {
    kovo_verify: noop,
    verify_replay_spec: noop,
    propose_chain_finding: noop,
    update_proposed_finding: noop,
    complete_intent: noop,
  }

  // Default active kovo_verify path: verify_replay_spec MUST be omitted.
  const activeTools = agentSession.buildWorkerTools(
    handlers,
    v => v,
    AbortSignal.timeout(5_000),
    64 * 1024,
    () => {},
  )
  const activeNames = activeTools.map(t => t.name)
  assert.ok(activeNames.includes('kovo_verify'))
  assert.equal(activeNames.includes('verify_replay_spec'), false, 'verify_replay_spec must be omitted when kovo_verify is active')

  // propose_chain_finding stays available for static_ast_proof with a trimmed, non-diluting description.
  const proposeTool = activeTools.find(t => t.name === 'propose_chain_finding')!
  assert.ok(proposeTool)
  assert.match(proposeTool.description, /static_ast_proof/)
  assert.equal(proposeTool.description.includes('- dns_takeover:'), false, 'retired runtime DSL schemas must not dilute tool prompt')
  assert.equal(proposeTool.description.includes('- sql_boolean_diff'), false, 'disabled runtime DSL schemas must not dilute tool prompt')
  assert.doesNotMatch(
    proposeTool.description,
    /\b(?:verify_replay_spec|http_chain|dns_takeover|tls_audit|browser_dom|ws_chain|upload_probe)\b/,
    'active kovo_verify propose_chain_finding description must not mention legacy verify_replay_spec or retired/runtime DSL kinds',
  )

  // Retired fail-closed DSL kinds are scrubbed from proposeChainFindingDescription in all modes,
  // while active legacy replay kinds remain intact when kovo_verify is absent.
  const legacyOnlyProposeDesc = agentPrompts.proposeChainFindingDescription(false)
  assert.match(legacyOnlyProposeDesc, /\bhttp_chain\b/)
  assert.doesNotMatch(
    legacyOnlyProposeDesc,
    /\b(?:dns_takeover|tls_audit|browser_dom|ws_chain|upload_probe)\b/,
    'retired fail-closed DSL kinds must stay scrubbed even in legacy replay-only mode',
  )

  // Proof-gap repair nudges scrub verify_replay_spec / DeclarativeReplaySpec when kovo_verify is active,
  // while keeping legacy replay-only sessions intact when kovo_verify is absent.
  const sampleRoute = { method: 'POST', path: '/api/v1/orders/:id', params: ['amount'] }
  const activeReqNudge = agentPrompts.specSubmissionRequiredMessage(sampleRoute, { hasKovoVerify: true })
  assert.match(activeReqNudge, /kovo_verify\(script=/)
  assert.doesNotMatch(activeReqNudge, /\bverify_replay_spec\b|DeclarativeReplaySpec/)
  const legacyReqNudge = agentPrompts.specSubmissionRequiredMessage(sampleRoute, { hasKovoVerify: false })
  assert.match(legacyReqNudge, /\bverify_replay_spec\b/)
  assert.ok(legacyReqNudge.includes(agentPrompts.KOVO_VERIFY_SPEC_SHAPE))

  const activeGapNudge = agentPrompts.gapValidationRejectedMessage(
    [{ key: 'POST /api/v1/orders/:id', code: 'auth_blocked', missing: 'a 401/403' }],
    sampleRoute,
    { hasKovoVerify: true },
  )
  assert.match(activeGapNudge, /kovo_verify\(script=/)
  assert.doesNotMatch(activeGapNudge, /\bverify_replay_spec\b|DeclarativeReplaySpec/)
  const legacyGapNudge = agentPrompts.gapValidationRejectedMessage(
    [{ key: 'POST /api/v1/orders/:id', code: 'auth_blocked', missing: 'a 401/403' }],
    sampleRoute,
    { hasKovoVerify: false },
  )
  assert.match(legacyGapNudge, /\bverify_replay_spec\b/)
  assert.ok(legacyGapNudge.includes(agentPrompts.KOVO_VERIFY_SPEC_SHAPE))

  // Explicit allowLegacyReplaySpec opt-in re-exposes verify_replay_spec (for legacy/static tests).
  const optedInTools = agentSession.buildWorkerTools(
    handlers,
    v => v,
    AbortSignal.timeout(5_000),
    64 * 1024,
    () => {},
    { allowLegacyReplaySpec: true },
  )
  assert.ok(optedInTools.some(t => t.name === 'verify_replay_spec'))

  // Without kovo_verify (replay-only mode), verify_replay_spec remains registered by default.
  const legacyOnlyTools = agentSession.buildWorkerTools(
    { verify_replay_spec: noop, propose_chain_finding: noop, complete_intent: noop },
    v => v,
    AbortSignal.timeout(5_000),
    64 * 1024,
    () => {},
  )
  assert.ok(legacyOnlyTools.some(t => t.name === 'verify_replay_spec'))
})

test('C1.4: runAgentSession omits verify_replay_spec from LLM request tool definitions when kovo_verify is active', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-arch-c1-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const seenToolNames: string[][] = []
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = []
    for await (const chunk of req) chunks.push(Buffer.from(chunk))
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { tools?: Array<{ name?: string }> }
    seenToolNames.push((body.tools ?? []).map(tool => String(tool.name ?? '')))
    const responseId = `resp_${randomUUID().slice(0, 8)}`
    const msgId = `msg_${randomUUID().slice(0, 8)}`
    const events = [
      { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } },
      { type: 'response.output_item.added', output_index: 0, item: { id: msgId, type: 'message', status: 'in_progress', role: 'assistant', content: [] } },
      { type: 'response.output_text.delta', output_index: 0, item_id: msgId, content_index: 0, delta: 'verified' },
      { type: 'response.output_text.done', output_index: 0, item_id: msgId, content_index: 0, text: 'verified' },
      { type: 'response.output_item.done', output_index: 0, item: { id: msgId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text: 'verified' }] } },
      {
        type: 'response.completed',
        response: {
          id: responseId,
          status: 'completed',
          output: [{ id: msgId, type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'verified' }] }],
          usage: { input_tokens: 40, output_tokens: 10, total_tokens: 50 },
        },
      },
    ]
    res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
      events.map(e => `data: ${JSON.stringify(e)}\n\n`).join('') + 'data: [DONE]\n\n',
    )
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => new Promise<void>(resolveClose => server.close(() => resolveClose())))
  const port = (server.address() as { port: number }).port

  const noop = async () => ({ ok: true })
  await agentSession.runAgentSession({
    directory: dir,
    sessionId: 'c1-hide-legacy',
    requestId: randomUUID(),
    settings: { endpoint: `http://127.0.0.1:${port}`, model: 'fixture-c1', protocol: 'responses', key: 'fixture-key-1234' },
    scenario: 'worker-investigation',
    prompt: 'Verify target',
    signal: AbortSignal.timeout(15_000),
    maxTurns: 1,
    enableSettlement: false,
    requireCompleteIntent: false,
    handlers: {
      kovo_verify: noop,
      verify_replay_spec: noop,
      propose_chain_finding: noop,
      complete_intent: noop,
    },
  })

  assert.equal(seenToolNames.length, 1)
  assert.ok(seenToolNames[0]!.includes('kovo_verify'))
  assert.equal(seenToolNames[0]!.includes('verify_replay_spec'), false, 'LLM must not receive verify_replay_spec when kovo_verify is active')
})

test('C1.5: replay-feedback.ts short-circuits retired DSL payloads with retriesRemaining=0 and zero v8 contamination', () => {
  const feedback = buildInlineVerifyFeedback(
    { kind: 'browser_chain' },
    {
      verdict: 'dismissed',
      outcome: {
        confirmed: false,
        controlPassed: false,
        observed: 'retired_legacy_spec_kind: use kovo_verify',
        expected: 'Proof submitted via kovo_verify.',
        reason: 'retired_legacy_spec_kind: use kovo_verify',
      },
      exchangeIds: [],
      exchanges: [],
      evidencePayload: { kind: 'browser_chain', retired: true, reason: 'retired_legacy_spec_kind: use kovo_verify' },
      evidenceSha256: 'retired-sha',
    },
    1,
    2,
  )
  assert.equal(feedback.verdict, 'dismissed')
  assert.equal(feedback.controlPassed, false)
  assert.equal(feedback.retriesRemaining, 0, 'retired legacy spec kinds must not advertise retries')
  assert.deepEqual(feedback.stepStatuses, [])
  assert.equal(feedback.verificationKind, 'browser_chain')

  const feedbackSrc = readFileSync(join(REPO_ROOT, 'src/server/replay-feedback.ts'), 'utf8')
  assert.equal(feedbackSrc.includes('domSnippet'), false, 'dead retired browser_dom/browser_chain domSnippet branch must be pruned')

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination hits: ${JSON.stringify(scan.hits)}`)
})
