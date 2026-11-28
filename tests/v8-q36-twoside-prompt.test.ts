/**
 * v8 Queue #36 Two-Side Confirmation Prompt/Playbook Closure & Residual v7-Compat Pruning Tests.
 *
 * Verifies (Docker-free, 100% generic, zero benchmark contamination):
 *  1. Rule 1 (no standalone terminal helper after setup hops): `multiHopDirectives`,
 *     `kovoVerifyPromptHint`, `kovoVerifyHelperGuidance`,
 *     `KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN`, `KOVO_VERIFY_TOOL_DESCRIPTION`,
 *     `workerSessionInstructions`, and `src/skills/multihop-chains.md` (excerpt + full playbook)
 *     instruct workers to ALWAYS finalize with `ctx.prove_composite` — NEVER standalone
 *     `prove_race_burst` / `prove_access_boundary` / `prove_persisted_mutation` — whenever a
 *     script executes prerequisite setup hops (disclosure/extraction, token/session acquisition,
 *     parser differential, cache prime, state rebind, or async job polling).
 *  2. Rule 2 (complete causal hop declaration): the same prompt & playbook surfaces instruct
 *     workers to declare EVERY executed causal hop from Hop 1 through intermediate hops to the
 *     terminal hop in `prove_composite.hops[]` connected with `causalEdges[]`, warning that
 *     omitting Hop 1 or intermediate hops yields an incomplete receipt.
 *  3. Residual v7-compat cleanup: `KOVO_VERIFY_SPEC_SHAPE` is removed from
 *     `kovoVerifyPromptHint()` and `kovoVerifyHelperGuidance()` (while remaining exported
 *     for legacy fallback callers), and zero-caller `deterministicLaneMaxWallClockMs` /
 *     `deterministicLaneWallClockShare` aliases are removed from `src/server/exec-dispatch.ts`.
 *  4. All prompt byte/line/excerpt budgets, single-hop isolation, and zero v8 contamination pass.
 */
import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { test } from 'node:test'

import {
  KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN,
  KOVO_VERIFY_SPEC_SHAPE,
  KOVO_VERIFY_TOOL_DESCRIPTION,
  kovoVerifyHelperGuidance,
  kovoVerifyPromptHint,
  workerInvestigationPrompt,
  workerSessionInstructions,
} from '../src/server/agent-prompts.ts'
import * as execDispatch from '../src/server/exec-dispatch.ts'
import {
  MULTIHOP_CHAINS_SKILL,
  clearSkillsCache,
  loadSkill,
  selectPreInjectionSkills,
} from '../src/server/skills.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)
const ORIGIN = 'https://q36-twoside.example.invalid'

type Q36MultiHopDirectives = {
  singleScriptConsolidation?: string
  compositeCallSignature?: string
}

function renderMultiHopDirectives(): Q36MultiHopDirectives {
  const parsed = JSON.parse(workerInvestigationPrompt({
    goal: 'Verify multi-stage cross-service workflow end-to-end',
    step: {
      id: 'step-q36-multihop',
      title: 'Clean-session chain · Parser differential, state rebind, and terminal impact',
      hypothesis: 'Stage 1 -> Stage 2 -> Stage 3 -> Terminal verification.',
      category: 'broken-access-control',
      skills: ['multihop-chains'],
    },
    origins: [ORIGIN],
    capabilityTier: 2,
    maxTurns: 12,
  })) as { multiHopDirectives?: Q36MultiHopDirectives }
  assert.ok(parsed.multiHopDirectives, 'multi-hop step must receive multiHopDirectives')
  return parsed.multiHopDirectives!
}

test('Q36.1: Rule 1 enforces ctx.prove_composite (never standalone terminal helpers) whenever prerequisite setup hops execute', () => {
  const directives = renderMultiHopDirectives()
  const consolidation = directives.singleScriptConsolidation ?? ''

  assert.match(consolidation, /ctx\.chain\(\.\.\.\) \/ ctx\.prove_composite/i)
  assert.match(consolidation, /never standalone helpers after setup hops/i)
  assert.match(consolidation, /prerequisite setup hops/i)

  const sysPrompt = workerSessionInstructions('worker-investigation', { hasKovoVerify: true })
  for (const [label, text] of [
    ['kovoVerifyPromptHint', kovoVerifyPromptHint()],
    ['kovoVerifyHelperGuidance', kovoVerifyHelperGuidance()],
    ['KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN', KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN],
    ['KOVO_VERIFY_TOOL_DESCRIPTION', KOVO_VERIFY_TOOL_DESCRIPTION],
    ['workerSessionInstructions', sysPrompt],
  ] as const) {
    assert.match(text, /prerequisite setup hops/i, `${label} must mention prerequisite setup hops`)
    assert.match(text, /NEVER standalone.*prove_race_burst/i, `${label} must forbid standalone prove_race_burst after setup hops`)
    assert.match(text, /prove_access_boundary/i, `${label} must mention prove_access_boundary`)
    assert.match(text, /prove_persisted_mutation/i, `${label} must mention prove_persisted_mutation`)
    assert.match(text, /prove_composite/i, `${label} must direct workers to prove_composite`)
  }

  clearSkillsCache()
  const playbook = loadSkill(MULTIHOP_CHAINS_SKILL)?.content ?? ''
  assert.match(playbook, /prerequisite setup hops/i)
  assert.match(playbook, /ctx\.prove_composite/i)
  assert.match(playbook, /rather than standalone single-hop helpers/i)
})

test('Q36.2: Rule 2 enforces declaring EVERY executed causal hop from Hop 1 through terminal in prove_composite.hops[] + causalEdges[]', () => {
  const directives = renderMultiHopDirectives()
  const consolidation = directives.singleScriptConsolidation ?? ''

  assert.match(consolidation, /every executed causal hop/i)
  assert.match(consolidation, /causalEdges\[\]/i)
  assert.match(consolidation, /terminalHopId/i)

  const sysPrompt = workerSessionInstructions('worker-investigation', { hasKovoVerify: true })
  for (const [label, text] of [
    ['kovoVerifyPromptHint', kovoVerifyPromptHint()],
    ['kovoVerifyHelperGuidance', kovoVerifyHelperGuidance()],
    ['KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN', KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN],
    ['KOVO_VERIFY_TOOL_DESCRIPTION', KOVO_VERIFY_TOOL_DESCRIPTION],
    ['workerSessionInstructions', sysPrompt],
  ] as const) {
    assert.match(text, /declare EVERY (?:executed )?causal hop/i, `${label} must require declaring every executed causal hop`)
    assert.match(text, /hops\[\]/i, `${label} must reference hops[]`)
    assert.match(text, /causalEdges\[\]/i, `${label} must reference causalEdges[]`)
  }

  for (const [label, text] of [
    ['KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN', KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN],
    ['KOVO_VERIFY_TOOL_DESCRIPTION', KOVO_VERIFY_TOOL_DESCRIPTION],
    ['workerSessionInstructions', sysPrompt],
  ] as const) {
    assert.match(text, /omitting Hop 1 or intermediate hops yields an incomplete receipt/i, `${label} must warn about incomplete receipts`)
  }

  clearSkillsCache()
  const playbook = loadSkill(MULTIHOP_CHAINS_SKILL)?.content ?? ''
  assert.match(playbook, /Declare every causal hop from Hop 1 through `terminalHopId`/i)
  assert.match(playbook, /causalEdges\[\]/i)
})

test('Q36.3: residual v7-compat cleanup removes KOVO_VERIFY_SPEC_SHAPE from kovo_verify summaries and dead lane aliases from exec-dispatch', () => {
  assert.equal(
    kovoVerifyPromptHint().includes(KOVO_VERIFY_SPEC_SHAPE),
    false,
    'kovoVerifyPromptHint must not append retired DeclarativeReplaySpec fields',
  )
  assert.equal(
    kovoVerifyHelperGuidance().includes(KOVO_VERIFY_SPEC_SHAPE),
    false,
    'kovoVerifyHelperGuidance must not append retired DeclarativeReplaySpec fields',
  )
  assert.equal(
    KOVO_VERIFY_TOOL_DESCRIPTION.includes(KOVO_VERIFY_SPEC_SHAPE),
    false,
    'KOVO_VERIFY_TOOL_DESCRIPTION must not append retired DeclarativeReplaySpec fields',
  )
  assert.ok(KOVO_VERIFY_SPEC_SHAPE.includes('DeclarativeReplaySpec'), 'legacy export remains available for fallback callers')

  assert.equal('deterministicLaneMaxWallClockMs' in execDispatch, false, 'dead alias deterministicLaneMaxWallClockMs must be removed')
  assert.equal('deterministicLaneWallClockShare' in execDispatch, false, 'dead alias deterministicLaneWallClockShare must be removed')
  assert.equal(typeof execDispatch.deterministicFloorMaxWallClockMs, 'number')
  assert.equal(typeof execDispatch.deterministicFloorWallClockShare, 'number')
})

test('Q36.4: prompt byte/line/excerpt budgets, single-hop isolation, and zero v8 contamination hold', () => {
  const guidanceBytes = Buffer.byteLength(kovoVerifyHelperGuidance(), 'utf8')
  const hintBytes = Buffer.byteLength(kovoVerifyPromptHint(), 'utf8')
  const patternLines = KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.split('\n').length

  assert.ok(
    guidanceBytes <= KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
    `kovoVerifyHelperGuidance() is ${guidanceBytes} B (> ${KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES} B)`,
  )
  assert.ok(hintBytes <= 512, `kovoVerifyPromptHint() is ${hintBytes} B (> 512 B)`)
  assert.ok(patternLines <= 12, `KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN has ${patternLines} lines (> 12)`)

  const singlePrompt = JSON.parse(workerInvestigationPrompt({
    goal: 'Check single endpoint response policy',
    step: {
      id: 'step-q36-single',
      title: 'Single-route header check',
      hypothesis: 'Inspect GET /api/v1/health response headers.',
      category: 'misconfig-exposure',
      skills: ['false-positive-elimination'],
    },
    origins: [ORIGIN],
    capabilityTier: 2,
    maxTurns: 6,
  })) as { multiHopDirectives?: unknown }
  assert.equal(singlePrompt.multiHopDirectives, undefined)

  clearSkillsCache()
  const mhSkill = selectPreInjectionSkills({ profileSkills: ['bola-idor-race'], lane: 'chain', limit: 2 })
    .find(s => s.name === MULTIHOP_CHAINS_SKILL)
  assert.ok(mhSkill)
  assert.ok(mhSkill!.excerpt.length <= 1200, `excerpt length ${mhSkill!.excerpt.length} > 1200`)
  assert.ok(mhSkill!.excerpt.includes('CompositeProofReceipt'), 'excerpt must preserve CompositeProofReceipt')

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination detected: ${JSON.stringify(scan.hits)}`)
  assert.equal(scan.hits.length, 0)
})
