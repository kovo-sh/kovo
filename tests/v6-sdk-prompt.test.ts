/**
 * v6 sdk-prompt stream: make the typed guardian_verify proof helpers discoverable and usable.
 *
 * Asserts the tool description advertises all five helpers plus the per-class hint map and the
 * repair-in-the-next-turn contract, that structured repair feedback (rejectedBy /
 * missingEvidence / transcriptSummary) reaches the model verbatim, that the guidance survives
 * slim skill catalogs and the 85% settlement gate, and that the added prompt text stays bounded.
 *
 * Fixtures are synthetic: no benchmark/app/route/seed literals, no external network.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  GUARDIAN_VERIFY_CLASS_HINTS,
  GUARDIAN_VERIFY_HELPERS,
  GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  GUARDIAN_VERIFY_REPAIR_INSTRUCTION,
  GUARDIAN_VERIFY_TOOL_DESCRIPTION,
  SPECIALIST_PROFILES,
  buildAgenticPromptContext,
  buildWorkerTools,
  filterHandlersForSpecialist,
  guardianVerifyHelperGuidance,
  guardianVerifyPromptHint,
  settlementBannerMessage,
  settlementNudgeMessage,
  settlementToolBlock,
  summarizeGuardianVerifyOutcome,
  workerInvestigationPrompt,
} from '../src/server/agent-session.ts'
import type { GuardianVerifyHandler, WorkerToolHandlers } from '../src/server/agent-session.ts'

const HELPER_NAMES = [
  'prove_access_boundary',
  'prove_persisted_mutation',
  'prove_boolean_or_timing_diff',
  'prove_oob_callback',
  'prove_race_burst',
] as const

const origin = 'https://app.example.invalid'

function buildTools(handlers: WorkerToolHandlers) {
  return buildWorkerTools(handlers, value => value, AbortSignal.timeout(5_000), 64 * 1024, () => {})
}

function toolByName(tools: ReturnType<typeof buildTools>, name: string) {
  return tools.find(tool => tool.name === name)
}

function textOf(result: { output?: readonly { type: string; text?: string }[] }): string {
  return (result.output ?? [])
    .filter(part => part.type === 'text')
    .map(part => part.text ?? '')
    .join('\n')
}

// ============================================================================
// 1. Tool description: helper names, usage, class hints, repair contract
// ============================================================================

test('helper guidance lists all five typed helpers with one-line usage', () => {
  for (const name of HELPER_NAMES) {
    assert.ok(GUARDIAN_VERIFY_TOOL_DESCRIPTION.includes(name), `description must name ${name}`)
  }
  assert.equal(GUARDIAN_VERIFY_HELPERS.length, 5)
  assert.deepEqual(GUARDIAN_VERIFY_HELPERS.map(helper => helper.name), [...HELPER_NAMES])
  for (const helper of GUARDIAN_VERIFY_HELPERS) {
    assert.ok(helper.use.length > 0, `${helper.name} needs a one-line usage`)
    assert.ok(
      GUARDIAN_VERIFY_TOOL_DESCRIPTION.includes(helper.use),
      `${helper.name} usage line must be part of the description`,
    )
  }
  // The original script-first contract is preserved verbatim.
  assert.match(GUARDIAN_VERIFY_TOOL_DESCRIPTION, /transcript oracle/i)
  assert.match(GUARDIAN_VERIFY_TOOL_DESCRIPTION, /stdout is never evidence/i)
})

test('class -> helper hints are present in the tool description', () => {
  assert.deepEqual(
    GUARDIAN_VERIFY_CLASS_HINTS.map(([klass, helper]) => `${klass} -> ${helper}`),
    [
      'authorization/BOLA -> prove_access_boundary',
      'mutation/BFLA/mass-assignment -> prove_persisted_mutation',
      'injection/timing -> prove_boolean_or_timing_diff',
      'SSRF/XXE/webhook -> prove_oob_callback',
      'race -> prove_race_burst',
    ],
  )
  for (const [klass, helper] of GUARDIAN_VERIFY_CLASS_HINTS) {
    assert.ok(GUARDIAN_VERIFY_TOOL_DESCRIPTION.includes(`${klass} -> ${helper}`), `missing hint ${klass}`)
  }
})

test('description instructs using rejectedBy/missingEvidence to repair, not abandon', () => {
  assert.match(GUARDIAN_VERIFY_TOOL_DESCRIPTION, /rejectedBy/)
  assert.match(GUARDIAN_VERIFY_TOOL_DESCRIPTION, /missingEvidence/)
  assert.match(GUARDIAN_VERIFY_TOOL_DESCRIPTION, /transcriptSummary/)
  assert.match(GUARDIAN_VERIFY_TOOL_DESCRIPTION, /repair/i)
  assert.match(GUARDIAN_VERIFY_TOOL_DESCRIPTION, /never abandon/i)
  assert.ok(GUARDIAN_VERIFY_TOOL_DESCRIPTION.includes(GUARDIAN_VERIFY_REPAIR_INSTRUCTION))
})

test('registered guardian_verify tool carries the helper guidance', () => {
  const handler: GuardianVerifyHandler = async () => ({ confirmed: false, reason: 'unconfirmed', detail: '', attempts: [] })
  const tool = toolByName(buildTools({ guardian_verify: handler }), 'guardian_verify')
  assert.ok(tool)
  for (const name of HELPER_NAMES) assert.ok(tool!.description.includes(name), `tool description must name ${name}`)
  assert.ok(tool!.description.includes(GUARDIAN_VERIFY_REPAIR_INSTRUCTION))
})

// ============================================================================
// 2. Structured repair feedback reaches the model verbatim
// ============================================================================

test('summarizeGuardianVerifyOutcome preserves rejectedBy/missingEvidence/transcriptSummary verbatim', () => {
  const transcriptSummary = [
    { exchangeId: 'ex-control', role: 'control', method: 'GET', pathAndQuery: '/api/orders/1', status: 403 },
    { exchangeId: 'ex-probe', role: 'probe', method: 'GET', pathAndQuery: '/api/orders/1', status: 200 },
  ]
  const result = summarizeGuardianVerifyOutcome({
    confirmed: false,
    reason: 'unconfirmed',
    detail: 'oracle rejected the proof',
    failures: ['boundary: access-control claim dismissed'],
    rejectedBy: 'boundary',
    missingEvidence: ['control_denied', 'variant_crossed'],
    transcriptSummary,
    attempts: [
      { attempt: 1, oraclePassed: false, exitCode: 0, exchangeCount: 2, transcriptDigest: 'digest-1', signaturesValid: true, failures: [] },
      { attempt: 2, oraclePassed: false, exitCode: 0, exchangeCount: 2, transcriptDigest: 'digest-2', signaturesValid: true, failures: [] },
    ],
  })
  assert.equal(result.confirmed, false)
  assert.equal(result.rejectedBy, 'boundary')
  assert.deepEqual(result.missingEvidence, ['control_denied', 'variant_crossed'])
  assert.deepEqual(result.transcriptSummary, transcriptSummary)
})

test('mocked handler result with missingEvidence is surfaced verbatim through the tool', async () => {
  const transcriptSummary = [
    { exchangeId: 'ex-control', role: 'control', method: 'GET', pathAndQuery: '/api/items/9', status: 403 },
    { exchangeId: 'ex-mutation', role: 'mutation', method: 'POST', pathAndQuery: '/api/items/9', status: 200 },
    { exchangeId: 'ex-after', role: 'after_get', method: 'GET', pathAndQuery: '/api/items/9', status: 200 },
  ]
  const handler: GuardianVerifyHandler = async () => ({
    confirmed: false,
    reason: 'unconfirmed',
    detail: 'missing the before_get arm',
    failures: ['impact: mutation claim requires a field delta'],
    rejectedBy: 'impact',
    missingEvidence: ['before_get', 'field_delta'],
    transcriptSummary,
    attempts: [
      { attempt: 1, oraclePassed: false, exitCode: 0, exchangeCount: 3, transcriptDigest: 'digest-a', signaturesValid: true, failures: [] },
      { attempt: 2, oraclePassed: false, exitCode: 0, exchangeCount: 3, transcriptDigest: 'digest-b', signaturesValid: true, failures: [] },
    ],
  })
  const tool = toolByName(buildTools({ guardian_verify: handler }), 'guardian_verify')
  assert.ok(tool)
  const result = await tool!.execute(
    { script: 'return ctx.result({ title: "mocked", claims: [] })' },
    {} as never,
    { abortSignal: AbortSignal.timeout(5_000) } as never,
  ) as { output?: readonly { type: string; text?: string }[]; isError?: boolean }
  assert.notEqual(result.isError, true)
  const payload = JSON.parse(textOf(result)) as {
    confirmed: boolean
    rejectedBy: string | null
    missingEvidence: string[]
    transcriptSummary: unknown[]
  }
  assert.equal(payload.confirmed, false)
  assert.equal(payload.rejectedBy, 'impact')
  assert.deepEqual(payload.missingEvidence, ['before_get', 'field_delta'])
  assert.deepEqual(payload.transcriptSummary, transcriptSummary)
})

test('legacy failure-line feedback is promoted into structured fields', () => {
  const result = summarizeGuardianVerifyOutcome({
    confirmed: false,
    reason: 'unconfirmed',
    detail: '',
    failures: [
      'rejected-by: oracle',
      'missing-evidence: control_denied',
      'missing-evidence: variant_crossed',
    ],
    attempts: [],
  })
  assert.equal(result.rejectedBy, 'oracle')
  assert.deepEqual(result.missingEvidence, ['control_denied', 'variant_crossed'])
})

// ============================================================================
// 3. Guidance survives slim catalogs, settlement, and stays bounded
// ============================================================================

test('per-class hint line survives an empty (fully slimmed) prompt context', () => {
  const context = buildAgenticPromptContext({})
  const micro = context.microTaskGuidance as { proofTools?: string }
  assert.ok(micro.proofTools, 'proof helper guidance must always be present')
  for (const name of HELPER_NAMES) assert.ok(micro.proofTools!.includes(name))
  assert.match(micro.proofTools!, /never abandon/i)
  assert.match(guardianVerifyPromptHint(), /rejectedBy/)
})

test('specialist profile catalogs keep the helper guidance on the tool description', () => {
  const handler: GuardianVerifyHandler = async () => ({ confirmed: false, reason: 'unconfirmed', detail: '', attempts: [] })
  for (const profile of Object.values(SPECIALIST_PROFILES)) {
    const scoped = filterHandlersForSpecialist({ guardian_verify: handler }, profile)
    assert.equal(typeof scoped.guardian_verify, 'function', `${profile.id} must keep guardian_verify`)
    const tool = toolByName(buildTools(scoped), 'guardian_verify')
    assert.ok(tool, `${profile.id} registers guardian_verify`)
    for (const name of HELPER_NAMES) assert.ok(tool!.description.includes(name), `${profile.id} lost ${name}`)
  }
})

test('slimmed investigation prompt still carries the helper guidance', () => {
  const prompt = workerInvestigationPrompt({
    goal: 'verify a candidate',
    step: { id: 'step-1', title: 'probe', hypothesis: 'authorization boundary', category: 'authz', skills: [] },
    origins: [origin],
    capabilityTier: 2,
    maxTurns: 8,
    availableSkills: [],
  })
  const parsed = JSON.parse(prompt) as { agenticContext: { microTaskGuidance: { proofTools?: string } } }
  for (const name of HELPER_NAMES) assert.ok(parsed.agenticContext.microTaskGuidance.proofTools!.includes(name))
})

test('settlement keeps guardian_verify available at the 85% threshold', () => {
  const maxTurns = 20
  const turnsUsed = Math.floor(maxTurns * 0.85)
  assert.equal(settlementToolBlock({ name: 'guardian_verify', settling: true, turnsUsed, maxTurns }), undefined)
  const banner = settlementBannerMessage({ turnsUsed, maxTurns, proofTools: ['guardian_verify'] })
  assert.match(banner, /guardian_verify/)
  assert.match(banner, /remain available/)
  const nudge = settlementNudgeMessage({ turn: maxTurns - 2, maxTurns, proofTools: ['guardian_verify'] })
  assert.match(nudge, /guardian_verify/)
})

test('added prompt text stays within the 2 KB budget', () => {
  const guidanceBytes = Buffer.byteLength(guardianVerifyHelperGuidance(), 'utf8')
  assert.ok(guidanceBytes <= GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES, `guidance is ${guidanceBytes} bytes`)
  assert.ok(Buffer.byteLength(guardianVerifyPromptHint(), 'utf8') <= 512, 'prompt hint line must stay compact')
})
