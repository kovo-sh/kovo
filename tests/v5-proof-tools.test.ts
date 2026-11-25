/**
 * Retirement contract for `src/server/proof-tools.ts` (Bucket-3 consolidation).
 *
 * The four legacy JSON-to-`http_chain` compilers (`prove_authz_read_diff`,
 * `prove_state_mutation_diff`, `prove_business_invariant`, `prove_canary_or_redirect`) were
 * superseded by `kovo_verify` (Layer-3 TypeScript SDK + independent transcript oracle +
 * ProofReceipt). `proof-tools.ts` remains only as a minimal type-only stub (`CompiledProof`).
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import * as proofTools from '../src/server/proof-tools.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

test('proof-tools.ts is retired to a minimal type-only stub with zero legacy compilers', () => {
  const src = readFileSync(join(repoRoot, 'src/server/proof-tools.ts'), 'utf8')
  const loc = src.split('\n').length
  assert.ok(loc <= 30, `retired proof-tools.ts must stay <= 30 LOC, got ${loc}`)
  assert.deepEqual([...proofTools.proofToolNames], [])
  assert.deepEqual(Object.keys(proofTools).sort(), ['proofToolNames'])
  for (const retired of [
    'proveAuthzReadDiff',
    'proveStateMutationDiff',
    'proveBusinessInvariant',
    'proveCanaryOrRedirect',
    'validateProofInput',
    'describeProofTools',
    'ProofCompileError',
  ]) {
    assert.equal(retired in proofTools, false, `${retired} must remain retired`)
  }
})
