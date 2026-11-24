/**
 * v7 guardian-verify-default — verifies `guardian_verify` is exposed on every specialist bundle
 * when registered (Docker backend) and clearly prioritized ahead of legacy `verify_replay_spec`
 * and `propose_chain_finding` across tool ordering, descriptions, system instructions, and repair
 * feedback.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  SPECIALIST_COMMON_TOOLS,
  SPECIALIST_PROFILES,
  buildWorkerTools,
  filterHandlersForSpecialist,
  proofToolHandlerNames,
  verifierRepairFeedback,
  withVerifierRepairFeedback,
  workerSessionInstructions,
} from '../src/server/agent-session.ts'
import type { WorkerToolHandlers } from '../src/server/agent-session.ts'

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
})
