/**
 * v8 Queue #33 Multi-Hop Proof Ergonomics Regression Tests
 * (`economic_conservation` baseline/final readbacks, `dag_topology` connected-DAG rule,
 * and derived session token injection without `as`/`persona`).
 *
 * Verifies (Docker-free, zero benchmark contamination):
 *  1. `economic_conservation` baseline -> action -> final readback pattern and host-hydrated
 *     `terminalImpact.oracleInput` (`baselineReadbackExchangeId`, `finalReadbackExchangeId`,
 *     `actionExchangeIds`, `equation`, `balancesBefore`/`paidAmount`) are clearly taught across
 *     `multiHopDirectives`, `KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN`,
 *     `KOVO_VERIFY_TOOL_DESCRIPTION`, `workerSessionInstructions`, `kovoVerifyHelperGuidance`,
 *     and `src/skills/multihop-chains.md` (pre-injected excerpt + full playbook).
 *  2. `dag_topology` connected-DAG rule (every hop in `hops[]` must connect via `causalEdges[]`
 *     on a path reaching `terminalImpact.terminalHopId`; never include unused/orphan exploratory hops)
 *     is enforced across all prompt/skill surfaces, and the documented `economic_conservation`
 *     receipt shape validates cleanly against `compositeProofReceiptSchema`.
 *  3. Derived session token injection rule (`kind: "bearer_token"`,
 *     `{ capability: { handle, target: "bearer" } }` or `{ headers: { Authorization: "Bearer " + handle } }`,
 *     and OMIT `as` / `persona`) is taught consistently across prompts, tool guidance, and playbook.
 *  4. All hard prompt budgets (`kovoVerifyHelperGuidance() <= 2048 B`,
 *     `kovoVerifyPromptHint() <= 512 B`, `KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN <= 12` lines,
 *     pre-injected `multihop-chains` excerpt retains `invariant_enforced_hardened`), stale-symbol bans,
 *     and zero v8 benchmark contamination pass cleanly.
 */
import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { test } from 'node:test'

import {
  KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN,
  KOVO_VERIFY_TOOL_DESCRIPTION,
  kovoVerifyHelperGuidance,
  kovoVerifyPromptHint,
  workerInvestigationPrompt,
  workerSessionInstructions,
} from '../src/server/agent-prompts.ts'
import { compositeProofReceiptSchema } from '../src/server/composite-receipt.ts'
import {
  MULTIHOP_CHAINS_SKILL,
  clearSkillsCache,
  loadSkill,
  selectPreInjectionSkills,
} from '../src/server/skills.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)
const ORIGIN = 'https://q33-docs.example.invalid'

type Q33MultiHopDirectives = {
  scopeAnchor?: string
  compositeCallSignature?: string
  singleScriptConsolidation?: string
  attackerProvenance?: string
  controlsAndReadback?: string
}

function renderMultiHopDirectives(): Q33MultiHopDirectives {
  const parsed = JSON.parse(workerInvestigationPrompt({
    goal: 'Verify cross-service workflow and state invariants',
    step: {
      id: 'step-q33-multihop',
      title: 'Clean-session chain · Session token exchange and state mutation',
      hypothesis: 'Stage 1 -> Stage 2 -> Stage 3 -> Terminal verification.',
      category: 'broken-access-control',
      skills: ['multihop-chains'],
    },
    origins: [ORIGIN],
    capabilityTier: 2,
    maxTurns: 12,
  })) as { multiHopDirectives?: Q33MultiHopDirectives }
  assert.ok(parsed.multiHopDirectives, 'multi-hop step must receive multiHopDirectives')
  return parsed.multiHopDirectives!
}

test('Q33.1: baseline + final readback discipline is documented across prompts and economic_conservation receipt schema validates', () => {
  const directives = renderMultiHopDirectives()
  const controlsDirective = directives.controlsAndReadback ?? ''

  assert.match(controlsDirective, /arm:\s*"control"/)
  assert.match(controlsDirective, /before mutating shared state/i)
  assert.match(controlsDirective, /post-chain readback exchange IDs/i)

  const sysPrompt = workerSessionInstructions('worker-investigation', { hasKovoVerify: true })
  for (const [label, text] of [
    ['KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN', KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN],
    ['KOVO_VERIFY_TOOL_DESCRIPTION', KOVO_VERIFY_TOOL_DESCRIPTION],
    ['workerSessionInstructions', sysPrompt],
  ] as const) {
    assert.match(text, /pre-chain baseline/i, `${label} missing pre-chain baseline reminder`)
    assert.match(text, /post-chain readback exchange IDs/i, `${label} missing post-chain readback reminder`)
  }

  // Documented economic_conservation receipt shape validates against live compositeProofReceiptSchema.
  const parsed = compositeProofReceiptSchema.safeParse({
    chainId: 'chain-econ-conservation-1',
    terminalVulnClass: 'economic_conservation',
    replayMode: 'fresh_clean_replay',
    hops: [
      {
        hopId: 'hop_1',
        surface: 'http',
        target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/ledger/credit' },
        exchangeIds: ['ex-act-1'],
        claimedDelta: 'Unconserved credit/payout executed.',
        producedCapabilities: [],
        consumedCapabilities: [],
      },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      claimedImpact: 'Final balance exceeds baseline + authorizedDeposits.',
      preChainControlExchangeIds: ['ex-base'],
      postChainReadbackExchangeIds: ['ex-after'],
      oracleInput: {
        equation: 'balance_minting',
        balancesBefore: { acct: 100 },
        balancesAfter: { acct: 200 },
        authorizedDeposits: 0,
        baselineReadbackExchangeId: 'ex-base',
        finalReadbackExchangeId: 'ex-after',
        actionExchangeIds: ['ex-act-1'],
      },
    },
  })
  assert.equal(parsed.success, true, `documented economic_conservation receipt must pass schema: ${JSON.stringify(parsed)}`)
})

test('Q33.2: dag_topology connected-DAG rule forbids unused/orphan exploratory hops in hops[]', () => {
  const directives = renderMultiHopDirectives()
  const dagDirective = directives.singleScriptConsolidation ?? ''

  assert.match(dagDirective, /connected via causalEdges\[\] to terminalHopId/i)

  const sysPrompt = workerSessionInstructions('worker-investigation', { hasKovoVerify: true })
  for (const [label, text] of [
    ['KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN', KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN],
    ['KOVO_VERIFY_TOOL_DESCRIPTION', KOVO_VERIFY_TOOL_DESCRIPTION],
    ['workerSessionInstructions', sysPrompt],
  ] as const) {
    assert.match(text, /dag_topology/, `${label} missing dag_topology`)
    assert.match(text, /terminalImpact\.terminalHopId/, `${label} missing terminalImpact.terminalHopId`)
    assert.match(text, /orphan exploratory hops/i, `${label} missing no-orphan-hops reminder`)
  }

  assert.match(kovoVerifyHelperGuidance(), /connected DAG \(no orphan hops\)/i)

  clearSkillsCache()
  const playbook = loadSkill(MULTIHOP_CHAINS_SKILL)?.content ?? ''
  assert.match(playbook, /causalEdges\[\]/i)
  assert.match(playbook, /no orphan exploratory hops/i)
})

test('Q33.3: derived session token injection rule teaches kind="bearer_token", target="bearer", and omitting as', () => {
  const sysPrompt = workerSessionInstructions('worker-investigation', { hasKovoVerify: true })
  for (const [label, text] of [
    ['KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN', KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN],
    ['KOVO_VERIFY_TOOL_DESCRIPTION', KOVO_VERIFY_TOOL_DESCRIPTION],
    ['workerSessionInstructions', sysPrompt],
  ] as const) {
    assert.match(text, /kind:\s*"bearer_token"/, `${label} missing kind: "bearer_token"`)
    assert.match(text, /target:\s*"bearer"/, `${label} missing target: "bearer"`)
    assert.match(text, /Authorization:\s*"Bearer "\s*\+\s*handle/, `${label} missing Authorization header fallback`)
    assert.match(text, /OMIT `as`\/`persona`/, `${label} missing OMIT as/persona rule`)
  }

  assert.match(kovoVerifyHelperGuidance(), /kind:"bearer_token".*target:"bearer".*OMIT as/i)

  clearSkillsCache()
  const playbook = loadSkill(MULTIHOP_CHAINS_SKILL)?.content ?? ''
  assert.match(playbook, /kind:\s*'bearer_token'/)
  assert.match(playbook, /target:\s*'bearer'/)
  assert.match(playbook, /omit `as`/i)
})

test('Q33.4: prompt byte/line budgets, pre-injection excerpt invariants, single-hop isolation, and zero v8 contamination hold', () => {
  const guidanceBytes = Buffer.byteLength(kovoVerifyHelperGuidance(), 'utf8')
  const hintBytes = Buffer.byteLength(kovoVerifyPromptHint(), 'utf8')
  const patternLines = KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.split('\n').length

  assert.ok(
    guidanceBytes <= KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
    `kovoVerifyHelperGuidance() is ${guidanceBytes} B (> ${KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES} B)`,
  )
  assert.ok(hintBytes <= 512, `kovoVerifyPromptHint() is ${hintBytes} B (> 512 B)`)
  assert.ok(patternLines <= 12, `KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN has ${patternLines} lines (> 12)`)

  // Single-hop step still omits multiHopDirectives.
  const singlePrompt = JSON.parse(workerInvestigationPrompt({
    goal: 'Check single endpoint response policy',
    step: {
      id: 'step-q33-single',
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

  // Pre-injected excerpt stays compact and has no stale SDK field names.
  clearSkillsCache()
  const mhSkill = selectPreInjectionSkills({ profileSkills: ['bola-idor-race'], lane: 'chain', limit: 2 })
    .find(s => s.name === MULTIHOP_CHAINS_SKILL)
  assert.ok(mhSkill)
  assert.ok(mhSkill!.excerpt.length <= 1200, `excerpt length ${mhSkill!.excerpt.length} > 1200`)
  assert.ok(mhSkill!.excerpt.includes('ctx.seal_capability'), 'excerpt must preserve ctx.seal_capability')
  assert.ok(mhSkill!.excerpt.includes('CompositeProofReceipt'), 'excerpt must preserve CompositeProofReceipt')

  const playbook = loadSkill(MULTIHOP_CHAINS_SKILL)?.content ?? ''
  for (const banned of ['fromExchangeId', 'rawValue', 'ctx.race(']) {
    assert.equal(playbook.includes(banned), false, `multihop-chains.md must not include ${banned}`)
  }

  // Zero v8 benchmark literals across src/server/** and src/skills/**.
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination detected: ${JSON.stringify(scan.hits)}`)
  assert.equal(scan.hits.length, 0)
})
