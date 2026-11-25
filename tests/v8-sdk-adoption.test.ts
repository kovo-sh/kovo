/**
 * v8 SDK Adoption Tests (Queue #18 Bottleneck #2).
 *
 * Verifies:
 *  1. `agent-session.ts` advertises v8 multi-hop SDK helpers (`ctx.seal_capability`,
 *     `ctx.http_send({ ..., capability })`, `ctx.hmac_sign`, `ctx.jwt_sign`, `ctx.await_async`,
 *     `ctx.prove_composite`), Mode A (`fresh_clean_replay`), and Attacker-Origin Provenance in
 *     `GUARDIAN_VERIFY_TOOL_DESCRIPTION`, `guardianVerifyHelperGuidance()`,
 *     `guardianVerifyPromptHint()`, and `workerSessionInstructions()`, while staying within all
 *     prompt byte budgets and preserving expanded 4 KB multi-hop briefs in `buildAgenticPromptContext`.
 *  2. `skills.ts` deterministically pre-injects `multihop-chains` for `chain` lane / multi-hop
 *     steps without regressing single-hop M1.4 pre-injection rankings.
 *  3. `assignment-brief.ts` renders `multiHopProofContract` (Attacker-Origin Provenance rule,
 *     <= 18-line Mode-A TS recipe with exact live SDK fields, optional crypto/async note, and
 *     Zero-FP Hardened-Twin rule) for chain/multi-hop briefs within budget, and omits it on
 *     single-hop briefs.
 *  4. Every SDK snippet field name in `src/skills/multihop-chains.md` and `MULTIHOP_MODE_A_TS_RECIPE`
 *     matches live `worker/guardian_verify/guardian_verify.ts`,
 *     `src/server/verify-rpc.ts`, and `compositeProofReceiptSchema` (zero stale field names).
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { test } from 'node:test'

import {
  GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  GUARDIAN_VERIFY_MULTIHOP_HELPERS,
  GUARDIAN_VERIFY_TOOL_DESCRIPTION,
  SPECIALIST_PROFILES,
  buildAgenticPromptContext,
  guardianVerifyHelperGuidance,
  guardianVerifyPromptHint,
  workerSessionInstructions,
} from '../src/server/agent-session.ts'
import {
  ASSIGNMENT_BRIEF_MAX_BYTES,
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  MULTIHOP_MODE_A_TS_RECIPE,
  buildAssignmentBriefPacket,
  type AssignmentBriefMultiHopContract,
} from '../src/server/assignment-brief.ts'
import { compositeProofReceiptSchema } from '../src/server/composite-receipt.ts'
import {
  MULTIHOP_CHAINS_SKILL,
  clearSkillsCache,
  isMultiHopChainAssignment,
  loadSkill,
  selectPreInjectionSkills,
} from '../src/server/skills.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)

// ============================================================================
// 1. guardian_verify tool description, helper guidance & system instructions
// ============================================================================

test('guardian_verify guidance, tool description, prompt hint, and system prompt advertise v8 multi-hop SDK helpers', () => {
  const expectedHelperNames = [
    'seal_capability',
    'http_send',
    'hmac_sign',
    'jwt_sign',
    'await_async',
    'prove_composite',
  ] as const

  assert.deepEqual(
    GUARDIAN_VERIFY_MULTIHOP_HELPERS.map(h => h.name),
    [...expectedHelperNames],
  )

  const guidance = guardianVerifyHelperGuidance()
  const hint = guardianVerifyPromptHint()
  const sysPrompt = workerSessionInstructions('worker-investigation', { hasGuardianVerify: true })

  // All 6 multi-hop helpers appear in the tool description, helper guidance, and active system prompt.
  for (const name of expectedHelperNames) {
    assert.ok(GUARDIAN_VERIFY_TOOL_DESCRIPTION.includes(`ctx.${name}`), `tool description missing ctx.${name}`)
    assert.ok(guidance.includes(`ctx.${name}`), `helper guidance missing ctx.${name}`)
    assert.ok(sysPrompt.includes(`ctx.${name}`), `system prompt missing ctx.${name}`)
  }

  // Compact prompt hint names the v8 multi-hop helpers and stays <= 512 B.
  for (const name of ['seal_capability', 'hmac_sign', 'jwt_sign', 'await_async', 'prove_composite']) {
    assert.ok(hint.includes(name), `prompt hint missing ${name}`)
  }
  assert.ok(Buffer.byteLength(hint, 'utf8') <= 512, `prompt hint ${Buffer.byteLength(hint, 'utf8')} B > 512 B`)
  assert.ok(
    Buffer.byteLength(guidance, 'utf8') <= GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
    `helper guidance ${Buffer.byteLength(guidance, 'utf8')} B > ${GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES} B`,
  )

  // Mode A + Attacker-Origin Provenance rule are explicitly present across all three surfaces.
  for (const [label, text] of [
    ['tool description', GUARDIAN_VERIFY_TOOL_DESCRIPTION],
    ['helper guidance', guidance],
    ['system prompt', sysPrompt],
  ] as const) {
    assert.match(text, /fresh_clean_replay/, `${label} must specify Mode A fresh_clean_replay`)
    assert.match(text, /low-priv/i, `${label} must specify low-privilege attacker origin`)
    assert.match(text, /never.*owner/i, `${label} must forbid pre-seeded owner persona on attack arm`)
  }
})

test('buildAgenticPromptContext preserves expanded <= 4 KB multi-hop assignment briefs without 1536 B truncation', () => {
  const packet = buildAssignmentBriefPacket({
    missionKind: 'multihop_chain',
    origin: 'https://api.example.test',
    routes: [
      { method: 'GET', path: '/api/v1/hop1', riskScore: 80 },
      { method: 'POST', path: '/api/v1/target', riskScore: 95 },
    ],
    personas: [
      { handle: 'member_b', role: 'member (org_b)' },
      { handle: 'owner_a', role: 'owner (org_a)' },
    ],
    hopCheckpoint: {
      branchKey: 'branch-1',
      depth: 2,
      verifiedHops: [{ hop: 1, receiptId: 'h1', capId: 'cap:hop_1:tok', surface: 'http', actor: 'member_b' }],
      capabilityHandles: ['cap:hop_1:tok'],
      nextGoal: { endpoint: 'POST /api/v1/target', goal: 'Pivot via cap:hop_1:tok' },
      doNotRediscover: true,
    },
  })
  assert.ok(packet.bytes > ASSIGNMENT_BRIEF_MAX_BYTES, 'multi-hop brief with checkpoint + contract exercises >1536 B path')
  assert.ok(packet.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)

  const ctx = buildAgenticPromptContext({ assignmentBrief: packet.text })
  assert.equal(ctx.evidenceBrief, packet.text, 'expanded multi-hop brief must not be truncated mid-JSON at 1536 B')
  assert.doesNotThrow(() => JSON.parse(String(ctx.evidenceBrief)))
})

// ============================================================================
// 2. Deterministic multihop-chains pre-injection in skills.ts
// ============================================================================

test('skills.ts deterministically pre-injects multihop-chains for chain lane and multi-hop steps without regressing M1.4', () => {
  clearSkillsCache()
  const bolaSkills = SPECIALIST_PROFILES['bola-bfla-specialist'].skills
  const authSkills = SPECIALIST_PROFILES['auth-session-oauth-specialist'].skills

  const multiHopCases = [
    { profileSkills: bolaSkills, lane: 'chain' },
    { profileSkills: authSkills, missionKind: 'chain' },
    { profileSkills: authSkills, missionKind: 'chain_step_2' },
    { profileSkills: bolaSkills, missionKind: 'multihop_chain' },
    { profileSkills: bolaSkills, category: 'chain' },
    { profileSkills: bolaSkills, category: 'chain_step' },
    { profileSkills: bolaSkills, stepSkills: ['chain:tenant-pivot'] },
    { profileSkills: bolaSkills, hasHopCheckpoint: true },
    { profileSkills: bolaSkills, hopDepth: 2 },
    { profileSkills: bolaSkills, title: '3-hop cross-tenant privilege escalation', hypothesis: 'Pivot from Hop 1 token to terminal write.' },
    { profileSkills: authSkills, title: 'Cross-service pivot via derived capability', hypothesis: 'Mint scoped token.' },
  ]

  for (const input of multiHopCases) {
    assert.equal(isMultiHopChainAssignment(input), true, `expected multi-hop match for ${JSON.stringify(input)}`)
    const skills = selectPreInjectionSkills({ ...input, limit: 2 })
    assert.ok(skills.some(s => s.name === MULTIHOP_CHAINS_SKILL), `expected multihop-chains for ${JSON.stringify(input)}`)
    const mh = skills.find(s => s.name === MULTIHOP_CHAINS_SKILL)!
    assert.ok(mh.excerpt.includes('ctx.seal_capability'))
    assert.ok(mh.excerpt.includes('ctx.prove_composite'))
    assert.ok(mh.excerpt.includes('invariant_enforced_hardened'))
  }

  // Single-hop M1.4 rankings must remain untouched.
  const singleHop = selectPreInjectionSkills({
    profileSkills: SPECIALIST_PROFILES['protocol-cache-edge-specialist'].skills,
    techTags: ['cdn'],
    sinkKind: 'redirect',
    title: 'Cache deception on authenticated route',
    limit: 2,
  })
  assert.ok(singleHop.some(s => s.name === 'cache-smuggling-desync'))
  assert.equal(singleHop.some(s => s.name === MULTIHOP_CHAINS_SKILL), false)

  // Bare "chain" word in generic single-hop det_lead stays single-hop.
  assert.equal(
    isMultiHopChainAssignment({
      profileSkills: bolaSkills,
      category: 'broken-access-control',
      title: 'det_lead upgrade GET /api/v1/orders/:id',
      hypothesis: 'Confirm BOLA and chain it if possible.',
    }),
    false,
  )
})

// ============================================================================
// 3. assignment-brief.ts multiHopProofContract & budget invariants
// ============================================================================

test('assignment-brief renders Mode-A prove_composite contract and Attacker-Origin rule on chain briefs within budget', () => {
  const recipeLines = MULTIHOP_MODE_A_TS_RECIPE.split('\n')
  assert.ok(recipeLines.length <= 18, `Mode-A TS recipe has ${recipeLines.length} lines (must be <= 18)`)

  for (const missionKind of ['chain_step_2', 'multihop_chain', 'second_order'] as const) {
    const packet = buildAssignmentBriefPacket({
      missionKind,
      origin: 'https://app.example.test',
      routes: [{ method: 'POST', path: '/api/v1/terminal', riskScore: 90 }],
      personas: [
        { handle: 'member_b', role: 'member (org_b)' },
        { handle: 'owner_a', role: 'owner (org_a)' },
      ],
    })
    assert.ok(packet.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE, `${missionKind} brief ${packet.bytes} B > 4 KB`)
    const parsed = JSON.parse(packet.text) as { multiHopProofContract?: AssignmentBriefMultiHopContract }
    const contract = parsed.multiHopProofContract
    assert.ok(contract, `${missionKind} must include multiHopProofContract`)
    assert.match(contract.attackerOriginRule, /low-privilege|cross-tenant/i)
    assert.match(contract.attackerOriginRule, /owner\/admin/i)
    assert.match(contract.hardenedTwinRule, /record_coverage\(status="ruled_out", proofGapReason="invariant_enforced_hardened"\)/)
    assert.match(contract.hardenedTwinRule, /complete_intent/)
    assert.ok(contract.optionalHelpers?.includes('ctx.hmac_sign'))
    assert.ok(contract.optionalHelpers?.includes('ctx.jwt_sign'))
    assert.ok(contract.optionalHelpers?.includes('ctx.await_async'))
    for (const token of [
      'ctx.http_send',
      'ctx.seal_capability',
      'capability: cap.handle',
      'ctx.prove_composite',
      'chainId',
      'terminalVulnClass',
      'replayMode: "fresh_clean_replay"',
      'hops:',
      'causalEdges:',
      'terminalImpact:',
      'return ctx.result',
    ]) {
      assert.ok(contract.modeATsRecipe.includes(token), `Mode-A TS recipe missing ${token}`)
    }
  }

  // Single-hop briefs omit multiHopProofContract and stay <= 1536 B.
  const singlePacket = buildAssignmentBriefPacket({
    missionKind: 'class_scan',
    origin: 'https://app.example.test',
    routes: [{ method: 'GET', path: '/api/v1/items', riskScore: 60 }],
  })
  assert.ok(singlePacket.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES)
  const singleParsed = JSON.parse(singlePacket.text) as { multiHopProofContract?: unknown }
  assert.equal(singleParsed.multiHopProofContract, undefined)

  // Tight explicit cap still yields valid JSON <= cap.
  const tightPacket = buildAssignmentBriefPacket(
    {
      missionKind: 'chain_step_2',
      origin: 'https://app.example.test',
      routes: [{ method: 'POST', path: '/api/v1/terminal' }],
    },
    1024,
  )
  assert.ok(tightPacket.bytes <= 1024)
  assert.doesNotThrow(() => JSON.parse(tightPacket.text))
})

// ============================================================================
// 4. Schema & live SDK signature alignment + zero contamination
// ============================================================================

test('multihop-chains.md and Mode-A recipe match live guardian_verify.ts, verify-rpc.ts, and compositeProofReceiptSchema', () => {
  clearSkillsCache()
  const playbook = loadSkill(MULTIHOP_CHAINS_SKILL)?.content ?? ''
  assert.ok(playbook.length > 0)

  const tsSdk = readFileSync(resolve(REPO_ROOT, 'worker/guardian_verify/guardian_verify.ts'), 'utf8')
  const verifyRpc = readFileSync(resolve(REPO_ROOT, 'src/server/verify-rpc.ts'), 'utf8')
  const compositeSrc = readFileSync(resolve(REPO_ROOT, 'src/server/composite-receipt.ts'), 'utf8')

  // Stale/non-existent field names must NEVER appear in the playbook.
  for (const stale of ['fromExchangeId', 'rawValue']) {
    assert.equal(playbook.includes(stale), false, `stale field ${stale} must not appear in multihop-chains.md`)
  }

  // Every TS SDK method taught in multihop-chains.md must exist verbatim in guardian_verify.ts.
  for (const method of [
    'seal_capability',
    'http_send',
    'hmac_sign',
    'jwt_sign',
    'await_async',
    'prove_composite',
  ] as const) {
    assert.ok(playbook.includes(`ctx.${method}`), `multihop-chains.md missing ctx.${method}`)
    assert.ok(tsSdk.includes(`${method}(`), `guardian_verify.ts missing method ${method}`)
  }

  // Every TS SDK input/output field taught in multihop-chains.md must exist verbatim in guardian_verify.ts + verify-rpc.ts.
  const tsSdkFields = [
    'exchangeId',
    'hopReceiptId',
    'slot',
    'jsonPath',
    'header',
    'cookie',
    'regex',
    'value',
    'kind',
    'ttlMs',
    'defaultHeaderName',
    'defaultCookieName',
    'allowedOrigins',
    'scrubbedPreview',
    'capability',
    'capabilityTarget',
    'capabilityHeaderName',
    'capabilityCookieName',
    'capabilityQueryParam',
    'consumedCapabilityId',
    'secretHandle',
    'payload',
    'alg',
    'encoding',
    'derivedFromCapabilityId',
    'claims',
    'derivedHandle',
    'pollRequest',
    'matchPredicate',
    'profile',
    'timeoutMs',
    'intervalMs',
    'maxAttempts',
    'triggerExchangeId',
    'tTriggerMs',
    'correlationId',
    'correlationIds',
    'entityId',
    'pollRecordId',
  ] as const
  for (const field of tsSdkFields) {
    assert.ok(playbook.includes(field), `multihop-chains.md missing live field ${field}`)
    assert.ok(tsSdk.includes(field), `guardian_verify.ts missing field ${field}`)
    assert.ok(verifyRpc.includes(field), `verify-rpc.ts missing field ${field}`)
  }

  // Every CompositeProofReceipt field taught in multihop-chains.md must exist in composite-receipt.ts.
  for (const receiptField of [
    'chainId',
    'terminalVulnClass',
    'replayMode',
    'fresh_clean_replay',
    'hops',
    'hopId',
    'surface',
    'pathAndQuery',
    'exchangeIds',
    'claimedDelta',
    'producedCapabilities',
    'consumedCapabilities',
    'causalEdges',
    'value_binding',
    'capabilityHandle',
    'derived_crypto_binding',
    'sourceCapabilityId',
    'state_transition_binding',
    'ablationExchangeIds',
    'async_pivot_binding',
    'pollRecordId',
    'terminalImpact',
    'terminalHopId',
    'claimedImpact',
    'preChainControlExchangeIds',
    'postChainReadbackExchangeIds',
  ]) {
    assert.ok(playbook.includes(receiptField), `multihop-chains.md missing receipt field ${receiptField}`)
    assert.ok(compositeSrc.includes(receiptField), `composite-receipt.ts missing receipt field ${receiptField}`)
  }

  // Validate a receipt matching the exact Mode-A recipe shape against the live Zod schema.
  const parsedReceipt = compositeProofReceiptSchema.safeParse({
    chainId: 'chain-1',
    terminalVulnClass: 'dual_tenant_abac',
    replayMode: 'fresh_clean_replay',
    hops: [
      {
        hopId: 'hop_1',
        surface: 'http',
        target: { origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/api/hop1' },
        exchangeIds: ['ex-1'],
        producedCapabilities: ['cap:hop_1:tok'],
        claimedDelta: 'Hop 1 capability obtained.',
      },
      {
        hopId: 'hop_2',
        surface: 'http',
        target: { origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/api/target' },
        exchangeIds: ['ex-2'],
        consumedCapabilities: ['cap:hop_1:tok'],
        claimedDelta: 'Hop 2 boundary crossed.',
      },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: 'cap:hop_1:tok' },
    ],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Unauthorized terminal access.',
      preChainControlExchangeIds: ['ex-ctrl'],
      postChainReadbackExchangeIds: ['ex-2'],
    },
  })
  assert.equal(parsedReceipt.success, true, `Mode-A recipe receipt failed Zod schema: ${JSON.stringify(parsedReceipt)}`)

  // Zero v8 benchmark contamination across src/server/ and src/skills/.
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination hits: ${JSON.stringify(scan.hits)}`)
})
