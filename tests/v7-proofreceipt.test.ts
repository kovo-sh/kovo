/**
 * v7 M0 — ProofReceipt unification tests.
 *
 * Cut 1 retires the agent-facing DSL plumbing (prove_* bindings, Phase-3 refinement queues).
 * Cut 2 adds the receipt primitive and the async OOB promotion path.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const executionSource = readFileSync(join(repoRoot, 'src/server/execution.ts'), 'utf8')

test('M0 cut 1: agent-facing prove_* compiler bindings are gone from Execution', () => {
  assert.ok(!executionSource.includes('submitProofSpec'))
  assert.ok(!executionSource.includes('prove_authz_read_diff:'))
  assert.ok(!executionSource.includes('prove_state_mutation_diff:'))
  assert.ok(!executionSource.includes('prove_business_invariant:'))
  assert.ok(!executionSource.includes('prove_canary_or_redirect:'))
  // proof-tools.ts stays for deterministic callers; Execution must not bind it to agents.
  assert.ok(!executionSource.includes("from './proof-tools.ts'"))
})

test('M0 cut 1: Phase-3 DSL refinement queue and fallback exposure are gone', () => {
  assert.ok(!executionSource.includes('refinementEligible'))
  assert.ok(!executionSource.includes('runPhase3RefinementJob'))
  assert.ok(!executionSource.includes('phase3RefinementAttempt'))
  assert.ok(!/stepId: `refine:/.test(executionSource))
  assert.ok(!executionSource.includes('Phase-3 refinement'))
})

test('M0: replay_spec_id stays nullable for historical findings', () => {
  const schema = readFileSync(join(repoRoot, 'src/server/schema.ts'), 'utf8')
  assert.match(schema, /replaySpecId: text\('replay_spec_id'\)(?!\.notNull)/)
})
