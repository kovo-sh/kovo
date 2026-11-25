/**
 * v7 M0 Cut 3f — replay-verifier decomposition.
 *
 * The verifier module is a thin validation/dispatch surface: agent-script proof execution lives in
 * `agent-script-proof.ts`, inline verification feedback in `replay-feedback.ts`, and the legacy
 * http_chain VM's assessment/receipt helpers in the recipe engine. These tests pin the LOC budget,
 * the re-export surface (no caller import breaks) and the floor-recipe wiring that remains.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'

import * as verifier from '../src/server/replay-verifier.ts'
import * as agentScript from '../src/server/agent-script-proof.ts'
import * as feedback from '../src/server/replay-feedback.ts'
import * as engine from '../src/server/floor-recipe-engine.ts'
import * as proofReceipt from '../src/server/proof-receipt.ts'
import {
  LEGACY_UNWIRED_SPECKINDS,
  WIRED_SPECKIND_RECIPES,
  wiredRecipeForSpecKind,
} from '../src/server/floor-recipes.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

function loc(rel: string): number {
  return readFileSync(join(repoRoot, rel), 'utf8').split('\n').length
}

describe('cut3f: replay-verifier is a thin module', () => {
  test('replay-verifier.ts is strictly under 1,000 lines', () => {
    const lines = loc('src/server/replay-verifier.ts')
    assert.ok(lines < 1000, `replay-verifier.ts is ${lines} lines; Cut 3f requires < 1000`)
  })

  test('the extracted modules own the code that left the verifier', () => {
    const verifierSource = readFileSync(join(repoRoot, 'src/server/replay-verifier.ts'), 'utf8')
    const agentSource = readFileSync(join(repoRoot, 'src/server/agent-script-proof.ts'), 'utf8')
    const feedbackSource = readFileSync(join(repoRoot, 'src/server/replay-feedback.ts'), 'utf8')

    assert.ok(agentSource.includes('export async function runAgentScriptProof'))
    assert.ok(agentSource.includes('export async function retestPersistedAgentScript'))
    assert.ok(agentSource.includes('export function persistedAgentScriptOf'))
    assert.ok(feedbackSource.includes('export function buildInlineVerifyFeedback'))
    assert.ok(feedbackSource.includes('export async function verifyReplaySpecInline'))
    assert.ok(feedbackSource.includes('function sanitizeInlinePreview'))
    assert.ok(feedbackSource.includes('function summarizeKeyResponseHeaders'))

    // The verifier must not re-implement the moved bodies.
    assert.ok(!verifierSource.includes('function sanitizeInlinePreview'))
    assert.ok(!verifierSource.includes('new VerifyRpcServer'))
    assert.ok(!verifierSource.includes('async function retestPersistedAgentScript'))
  })

  test('the assessment/receipt helpers live in the recipe engine while the VM stays thin', () => {
    const engineSource = readFileSync(join(repoRoot, 'src/server/floor-recipe-engine.ts'), 'utf8')
    const verifierSource = readFileSync(join(repoRoot, 'src/server/replay-verifier.ts'), 'utf8')
    for (const symbol of [
      'export function assessBflaImpact',
      'export function assessHttpChainProofStrength',
      'export function assessHttpChainEndpointBinding',
      'export function classifyHttpChainAssertion',
      'export function buildReplayReceipt',
      'export function applyReceiptGate',
      'export function inconclusiveResult',
      'export function proofReceiptMode',
    ]) {
      assert.ok(engineSource.includes(symbol), `${symbol} must live in floor-recipe-engine.ts`)
    }
    // The legacy VM body stays in the verifier (behavioural parity for benchmark-specs-*/deterministic
    // specs), but it now consumes the extracted helpers instead of owning them.
    assert.ok(verifierSource.includes('const bflaImpact = assessBflaImpact(spec, stepsOut)'))
    assert.ok(verifierSource.includes('forcedInconclusiveReason = bflaImpact.reason'))
    assert.ok(verifierSource.includes('singleQuoteEscape(spec.assertionsJq)'))
  })
})

describe('cut3f: re-export surface', () => {
  test('every moved public symbol is still importable from replay-verifier', () => {
    for (const name of [
      'runAgentScriptProof',
      'retestPersistedAgentScript',
      'persistedAgentScriptOf',
      'buildInlineVerifyFeedback',
      'verifyReplaySpecInline',
      'inconclusiveResult',
      'proofReceiptMode',
      'assessBflaImpact',
      'assessHttpChainProofStrength',
      'assessHttpChainEndpointBinding',
      'classifyHttpChainAssertion',
      'buildReplayReceipt',
      'applyReceiptGate',
      'impactStepsFromStepsOut',
      'verifyReplaySpec',
      'retestReplaySpec',
      'assertNotRecipeWiredLegacyCall',
    ]) {
      assert.ok(name in verifier, `${name} must be re-exported from replay-verifier.ts`)
    }
    assert.equal(typeof verifier.runAgentScriptProof, 'function')
    assert.equal(verifier.runAgentScriptProof, agentScript.runAgentScriptProof)
    assert.equal(verifier.buildInlineVerifyFeedback, feedback.buildInlineVerifyFeedback)
    assert.equal(verifier.verifyReplaySpecInline, feedback.verifyReplaySpecInline)
    assert.equal(verifier.inconclusiveResult, engine.inconclusiveResult)
    assert.equal(verifier.proofReceiptMode, proofReceipt.proofReceiptMode)
    assert.equal(verifier.proofReceiptMode({} as NodeJS.ProcessEnv), 'strict')
    assert.ok(verifier.RETIRED_LEGACY_SPEC_KINDS.has('browser_chain'))
  })
})

describe('cut3f: floor recipe wiring', () => {
  test('the wired pairs still resolve to their typed recipes', () => {
    const expected: Array<[string, string, string]> = [
      ['sql_boolean_diff', 'sqli', 'boolean_or_timing'],
      ['sql_time_diff', 'sqli', 'boolean_or_timing'],
      ['race_burst', 'race_double_spend', 'conserved_balance'],
      ['browser_chain', 'xss_reflected', 'browser_sink'],
      ['http_chain', 'bola', 'access_boundary'],
      ['http_chain', 'bfla', 'access_boundary'],
      ['http_chain', 'cross_tenant_write', 'access_boundary'],
    ]
    for (const [kind, vulnClass, recipe] of expected) {
      assert.equal(wiredRecipeForSpecKind(kind, vulnClass), recipe, `${kind}/${vulnClass}`)
    }
    assert.ok(WIRED_SPECKIND_RECIPES.length >= 5)
  })

  test('recipe envelopes dispatch before the retired-kind gate (no caller regression)', async () => {
    // A retired kind carrying a floorRecipe envelope must still run its recipe: this is the
    // dispatch order the extraction preserved. We assert the pure helpers rather than a live run.
    const source = readFileSync(join(repoRoot, 'src/server/replay-verifier.ts'), 'utf8')
    const recipeDispatch = source.indexOf('const persistedRecipe = persistedRecipeOf(params.spec)')
    const retiredGate = source.indexOf('if (RETIRED_LEGACY_SPEC_KINDS.has(spec.kind))')
    assert.ok(recipeDispatch > 0 && retiredGate > 0)
    assert.ok(recipeDispatch < retiredGate, 'recipe dispatch must run before retired-kind rejection')
  })

  test('http_chain classes not yet flipped stay explicitly documented, never silently legacy', () => {
    // Flipping these pairs changes the pinned no-fallback contract (v7-cut3a/cut3b) and the live
    // engine's candidate routing. They remain on the legacy path with a named reason; the recipes
    // themselves are executable for any spec that carries an envelope.
    for (const vulnClass of ['mass_assignment', 'workflow_bypass', 'business_logic', 'csrf', 'info_disclosure', 'ssrf', 'xxe']) {
      assert.equal(wiredRecipeForSpecKind('http_chain', vulnClass), null, `${vulnClass} must stay legacy in this cut`)
      const row = LEGACY_UNWIRED_SPECKINDS.find(entry => entry.specKind === 'http_chain' && entry.vulnClasses.includes(vulnClass))
      assert.ok(row, `${vulnClass} must have a documented legacy reason`)
      assert.ok(row!.reason.length > 20)
    }
  })
})
