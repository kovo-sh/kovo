// ChainOracle soundness: completion requires ordered hops + final impact under one causal artifact.
// Out-of-order, incomplete, cross-artifact and pre-impact-final streams must never complete.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createChainOracle, causalArtifactOf } from '../lib/chain-oracle.ts'
import type { CausalChainSpec, OracleEvent } from '../lib/types.ts'

const SPEC: CausalChainSpec = {
  id: 'lf-13-chain',
  hops: [
    { hopId: 'h1-feed', routeKey: 'team.feed', kind: 'cross_tenant_read' },
    { hopId: 'h2-delegate', routeKey: 'payout.delegate', kind: 'self_approval_bypass', requiresPrior: ['h1-feed'] },
  ],
  finalImpactKind: 'causal_chain_completed',
  finalRouteKey: 'payout.approve',
}

const ART = 'apv_9f2c'

function recordHop(o: ReturnType<typeof createChainOracle>, hopId: string, ts: number, artifact = ART): void {
  const hop = SPEC.hops.find((h) => h.hopId === hopId)!
  o.record({ hopId, routeKey: hop.routeKey, kind: hop.kind, actor: 'member_a', artifact, ts })
}
function recordFinal(o: ReturnType<typeof createChainOracle>, ts: number, artifact = ART): void {
  o.record({ routeKey: SPEC.finalRouteKey, kind: SPEC.finalImpactKind, actor: 'member_a', artifact, ts })
}

test('ordered hops sharing one artifact plus final impact complete the chain', () => {
  const o = createChainOracle()
  recordHop(o, 'h1-feed', 1000)
  recordHop(o, 'h2-delegate', 2000)
  recordFinal(o, 3000)
  const c = o.completed(SPEC)
  assert.equal(c.completed, true)
  assert.equal(c.hopsObserved, 2)
  assert.equal(c.hopsTotal, 2)
  assert.equal(c.finalObserved, true)
  assert.equal(c.artifact, ART)
  assert.deepEqual(c.completedHopIds, ['h1-feed', 'h2-delegate'])
})

test('a missing hop is incomplete even when the final impact fired', () => {
  const o = createChainOracle()
  recordHop(o, 'h1-feed', 1000)
  recordFinal(o, 3000)
  const c = o.completed(SPEC)
  assert.equal(c.completed, false)
  assert.equal(c.hopsObserved, 1)
  assert.deepEqual(c.missingHopIds, ['h2-delegate'])
})

test('out-of-order hops do not complete', () => {
  const o = createChainOracle()
  recordHop(o, 'h2-delegate', 1000)
  recordHop(o, 'h1-feed', 2000)
  recordFinal(o, 3000)
  const c = o.completed(SPEC)
  assert.equal(c.completed, false)
  assert.ok(c.reason.includes('not observed in order'))
})

test('hops split across different causal artifacts do not complete', () => {
  const o = createChainOracle()
  recordHop(o, 'h1-feed', 1000, 'artifact-A')
  recordHop(o, 'h2-delegate', 2000, 'artifact-B')
  recordFinal(o, 3000, 'artifact-A')
  const c = o.completed(SPEC)
  assert.equal(c.completed, false)
})

test('final impact before the last hop does not complete', () => {
  const o = createChainOracle()
  recordFinal(o, 500)
  recordHop(o, 'h1-feed', 1000)
  recordHop(o, 'h2-delegate', 2000)
  const c = o.completed(SPEC)
  assert.equal(c.completed, false)
  assert.equal(c.finalObserved, false)
})

test('requiresPrior is enforced independently of timestamp order', () => {
  const o = createChainOracle()
  // h2 arrives first in time; even if h1 arrives later, h2 cannot be credited before its prior.
  recordHop(o, 'h2-delegate', 1000)
  recordHop(o, 'h1-feed', 2000)
  recordFinal(o, 3000)
  const c = o.completed(SPEC)
  assert.equal(c.completed, false)
  assert.ok(c.reason.includes('requires prior') || c.reason.includes('not observed'))
})

test('recordOracleEvent maps detail.artifact onto chain hops and final impact', () => {
  const o = createChainOracle()
  const mk = (seq: number, kind: OracleEvent['kind'], routeKey: string, ts: number): OracleEvent => ({
    seq, ts, kind, app: 'ledgerflow', routeKey, method: 'POST', path: `/${routeKey}`,
    actor: 'member_a', detail: { artifact: ART },
  })
  o.recordOracleEvent(mk(0, 'cross_tenant_read', 'team.feed', 1000), [SPEC])
  o.recordOracleEvent(mk(1, 'self_approval_bypass', 'payout.delegate', 2000), [SPEC])
  o.recordOracleEvent(mk(2, 'causal_chain_completed', 'payout.approve', 3000), [SPEC])
  const c = o.completed(SPEC)
  assert.equal(c.completed, true)
  assert.equal(o.events().length, 3)
})

test('oracle events without a causal artifact are never credited', () => {
  const o = createChainOracle()
  const ev: OracleEvent = {
    seq: 0, ts: 1000, kind: 'causal_chain_completed', app: 'ledgerflow',
    routeKey: 'payout.approve', method: 'POST', path: '/payout/approve',
    actor: 'member_a', detail: {},
  }
  assert.equal(o.recordOracleEvent(ev, [SPEC]), 0)
  assert.equal(o.events().length, 0)
  assert.equal(o.completed(SPEC).completed, false)
})

test('causalArtifactOf accepts the documented aliases', () => {
  assert.equal(causalArtifactOf({ artifact: 'a1' }), 'a1')
  assert.equal(causalArtifactOf({ causalArtifact: 'a2' }), 'a2')
  assert.equal(causalArtifactOf({ chainArtifact: 'a3' }), 'a3')
  assert.equal(causalArtifactOf({ correlationId: 'a4' }), 'a4')
  assert.equal(causalArtifactOf({}), '')
})

test('reset clears recorded hops', () => {
  const o = createChainOracle()
  recordHop(o, 'h1-feed', 1000)
  recordHop(o, 'h2-delegate', 2000)
  recordFinal(o, 3000)
  assert.equal(o.completed(SPEC).completed, true)
  o.reset()
  assert.equal(o.events().length, 0)
  assert.equal(o.completed(SPEC).completed, false)
})
