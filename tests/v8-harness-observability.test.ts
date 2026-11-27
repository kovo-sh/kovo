/**
 * Harness observability unit tests for `benchmarks/multihop-saas/run.ts`.
 *
 * Verifies that `ChainOracle`'s diagnostic `failureReason` and `missingHopIds`
 * survive serialization on each chain object in `chains[]` across:
 *  - persona shortcut rejections (naming the exact disallowed persona),
 *  - edge-binding rejections (naming the exact binding/control mismatch),
 *  - partial-hop chains (and fallback when only `oracleEvents` are provided),
 *  - confirmed two-side chains (`failureReason: null`, `missingHopIds: []`)
 * without altering any existing grading or scoring behavior.
 */
import assert from 'node:assert/strict'
import test from 'node:test'

import { createChainOracle, sha256 } from '../benchmarks/multihop-saas/lib/chain-oracle.ts'
import type { ChainSpec, GroundTruth } from '../benchmarks/multihop-saas/lib/types.ts'
import {
  gradeRun,
  renderScorecard,
  type ProductScorecard,
} from '../benchmarks/multihop-saas/run.ts'
import {
  evaluateTwoSideConfirmation,
  type SubmittedCompositeProof,
} from '../scripts/benchmark-multihop.ts'

const SPECS: readonly ChainSpec[] = [
  {
    id: 'obs-shortcut-hop',
    title: 'Shortcut persona at intermediate hop',
    vulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'h1', service: 'api', routeKey: 'api.step1', actor: 'member_a' },
      { hopId: 'h2', service: 'api', routeKey: 'api.step2', actor: 'member_a', edgeFromPrevious: 'value_binding' },
      { hopId: 'h3', service: 'api', routeKey: 'api.step3', actor: 'member_a', edgeFromPrevious: 'value_binding' },
    ],
    terminal: { service: 'api', routeKey: 'api.step3', kind: 'cross_tenant_export' },
    attackerPersonaSet: ['member_a', 'dual_member'],
    forbiddenShortcutPersonas: ['owner_a', 'admin_bot'],
  },
  {
    id: 'obs-shortcut-terminal',
    title: 'Shortcut persona at terminal impact',
    vulnClass: 'cross_tenant_export',
    hops: [
      { hopId: 'h1', service: 'api', routeKey: 'api.t1', actor: 'member_a' },
      { hopId: 'h2', service: 'api', routeKey: 'api.t2', actor: 'member_a', edgeFromPrevious: 'value_binding' },
    ],
    terminal: { service: 'api', routeKey: 'api.t2', kind: 'cross_tenant_export' },
    attackerPersonaSet: ['member_a'],
    forbiddenShortcutPersonas: ['owner_a', 'admin_bot'],
  },
  {
    id: 'obs-edge-value',
    title: 'Value binding mismatch between hops',
    vulnClass: 'forged_settlement',
    hops: [
      { hopId: 'h1', service: 'api', routeKey: 'api.v1', actor: 'member_a' },
      { hopId: 'h2', service: 'api', routeKey: 'api.v2', actor: 'member_a', edgeFromPrevious: 'value_binding' },
      { hopId: 'h3', service: 'api', routeKey: 'api.v3', actor: 'member_a', edgeFromPrevious: 'value_binding' },
    ],
    terminal: { service: 'api', routeKey: 'api.v3', kind: 'forged_settlement' },
    attackerPersonaSet: ['member_a'],
    forbiddenShortcutPersonas: ['owner_a', 'admin_bot'],
  },
  {
    id: 'obs-edge-control',
    title: 'State transition binding missing clean ablation control',
    vulnClass: 'self_approved_payout',
    hops: [
      { hopId: 'h1', service: 'api', routeKey: 'api.c1', actor: 'member_a' },
      { hopId: 'h2', service: 'api', routeKey: 'api.c2', actor: 'member_a', edgeFromPrevious: 'state_transition_binding' },
      { hopId: 'h3', service: 'api', routeKey: 'api.c3', actor: 'member_a', edgeFromPrevious: 'value_binding' },
    ],
    terminal: { service: 'api', routeKey: 'api.c3', kind: 'self_approved_payout' },
    attackerPersonaSet: ['member_a'],
    forbiddenShortcutPersonas: ['owner_a', 'admin_bot'],
  },
  {
    id: 'obs-partial-hop',
    title: 'Partial hop progression',
    vulnClass: 'ledger_overcredit',
    hops: [
      { hopId: 'h1', service: 'api', routeKey: 'api.p1', actor: 'member_a' },
      { hopId: 'h2', service: 'api', routeKey: 'api.p2', actor: 'member_a', edgeFromPrevious: 'value_binding' },
      { hopId: 'h3', service: 'api', routeKey: 'api.p3', actor: 'member_a', edgeFromPrevious: 'value_binding' },
    ],
    terminal: { service: 'api', routeKey: 'api.p3', kind: 'ledger_overcredit' },
    attackerPersonaSet: ['member_a'],
    forbiddenShortcutPersonas: ['owner_a', 'admin_bot'],
  },
  {
    id: 'obs-confirmed',
    title: 'Complete two-side confirmed chain',
    vulnClass: 'cross_tenant_secret_read',
    hops: [
      { hopId: 'h1', service: 'api', routeKey: 'api.ok1', actor: 'member_a' },
      { hopId: 'h2', service: 'api', routeKey: 'api.ok2', actor: 'member_a', edgeFromPrevious: 'value_binding' },
    ],
    terminal: { service: 'api', routeKey: 'api.ok2', kind: 'cross_tenant_secret_read' },
    attackerPersonaSet: ['member_a'],
    forbiddenShortcutPersonas: ['owner_a', 'admin_bot'],
  },
]

function makeGroundTruth(specs: readonly ChainSpec[]): GroundTruth {
  return {
    app: 'paygrid',
    seed: 42,
    seedSet: 'dev',
    labMode: 'vulnerable',
    expectedChains: specs.map((spec) => ({
      chainId: spec.id,
      vulnClass: spec.vulnClass,
      hopIds: spec.hops.map((h) => h.hopId),
      edgeKinds: spec.hops.flatMap((h) => (h.edgeFromPrevious ? [h.edgeFromPrevious] : [])),
      terminalKind: spec.terminal.kind,
    })),
    twinDecoys: [],
    topology: [{ id: 'api', role: 'api', internal: false }],
    personas: [
      { id: 'member_a', tenantId: 'org_a', rolesByTenant: { org_a: 'member' } },
      { id: 'owner_a', tenantId: 'org_a', rolesByTenant: { org_a: 'owner' } },
    ],
  }
}

test('gradeRun and JSON serialization preserve failureReason and missingHopIds across shortcut, edge-binding, partial-hop, and confirmed chains', () => {
  let tick = 1_000
  const oracle = createChainOracle({
    runId: 'run-obs-1a',
    specs: SPECS,
    clock: () => {
      tick += 10
      return tick
    },
  })

  // 1a. Shortcut at intermediate hop (owner_a executes h2 after member_a executes h1)
  const s1Digest = sha256('shortcut-h1')
  oracle.recordHop({
    chainId: 'obs-shortcut-hop',
    hopId: 'h1',
    service: 'api',
    routeKey: 'api.step1',
    actor: 'member_a',
    artifactDigest: s1Digest,
  })
  oracle.recordHop({
    chainId: 'obs-shortcut-hop',
    hopId: 'h2',
    service: 'api',
    routeKey: 'api.step2',
    actor: 'owner_a',
    artifactDigest: sha256('shortcut-h2'),
  })

  // 1b. Shortcut at terminal (all hops attacker-eligible, terminal executed by admin_bot)
  const st1 = sha256('st-h1')
  oracle.recordHop({
    chainId: 'obs-shortcut-terminal',
    hopId: 'h1',
    service: 'api',
    routeKey: 'api.t1',
    actor: 'member_a',
    artifactDigest: st1,
  })
  oracle.recordHop({
    chainId: 'obs-shortcut-terminal',
    hopId: 'h2',
    service: 'api',
    routeKey: 'api.t2',
    actor: 'member_a',
    artifactDigest: sha256('st-h2'),
  })
  oracle.recordEdge({
    chainId: 'obs-shortcut-terminal',
    fromHopId: 'h1',
    toHopId: 'h2',
    kind: 'value_binding',
    fromArtifactDigest: st1,
    toConsumedDigest: st1,
  })
  oracle.recordTerminal({
    chainId: 'obs-shortcut-terminal',
    service: 'api',
    routeKey: 'api.t2',
    kind: 'cross_tenant_export',
    actor: 'admin_bot',
  })

  // 2a. Edge binding rejected: value_binding mismatch
  const ev1 = sha256('ev-h1')
  oracle.recordHop({
    chainId: 'obs-edge-value',
    hopId: 'h1',
    service: 'api',
    routeKey: 'api.v1',
    actor: 'member_a',
    artifactDigest: ev1,
  })
  oracle.recordHop({
    chainId: 'obs-edge-value',
    hopId: 'h2',
    service: 'api',
    routeKey: 'api.v2',
    actor: 'member_a',
    artifactDigest: sha256('ev-h2'),
  })
  oracle.recordEdge({
    chainId: 'obs-edge-value',
    fromHopId: 'h1',
    toHopId: 'h2',
    kind: 'value_binding',
    fromArtifactDigest: ev1,
    toConsumedDigest: sha256('wrong-consumed-digest'),
  })

  // 2b. Edge binding rejected: state_transition_binding missing clean ablation control
  const ec1 = sha256('ec-h1')
  oracle.recordHop({
    chainId: 'obs-edge-control',
    hopId: 'h1',
    service: 'api',
    routeKey: 'api.c1',
    actor: 'member_a',
    artifactDigest: ec1,
    entityId: 'payout-99',
  })
  oracle.recordHop({
    chainId: 'obs-edge-control',
    hopId: 'h2',
    service: 'api',
    routeKey: 'api.c2',
    actor: 'member_a',
    artifactDigest: sha256('ec-h2'),
    entityId: 'payout-99',
  })
  oracle.recordEdge({
    chainId: 'obs-edge-control',
    fromHopId: 'h1',
    toHopId: 'h2',
    kind: 'state_transition_binding',
    fromArtifactDigest: ec1,
    toConsumedDigest: ec1,
    entityId: 'payout-99',
  })

  // 3. Partial hop: only h1 observed (missing h2, h3)
  oracle.recordHop({
    chainId: 'obs-partial-hop',
    hopId: 'h1',
    service: 'api',
    routeKey: 'api.p1',
    actor: 'member_a',
    artifactDigest: sha256('partial-h1'),
  })

  // 4. Confirmed chain: complete oracle DAG (WITHOUT oracle.mintReceipt, matching real product runs)
  const ok1 = sha256('ok-h1')
  oracle.recordHop({
    chainId: 'obs-confirmed',
    hopId: 'h1',
    service: 'api',
    routeKey: 'api.ok1',
    actor: 'member_a',
    artifactDigest: ok1,
  })
  oracle.recordHop({
    chainId: 'obs-confirmed',
    hopId: 'h2',
    service: 'api',
    routeKey: 'api.ok2',
    actor: 'member_a',
    artifactDigest: sha256('ok-h2'),
  })
  oracle.recordEdge({
    chainId: 'obs-confirmed',
    fromHopId: 'h1',
    toHopId: 'h2',
    kind: 'value_binding',
    fromArtifactDigest: ok1,
    toConsumedDigest: ok1,
  })
  oracle.recordTerminal({
    chainId: 'obs-confirmed',
    service: 'api',
    routeKey: 'api.ok2',
    kind: 'cross_tenant_secret_read',
    actor: 'member_a',
  })

  const compositeReceipts: SubmittedCompositeProof[] = [
    {
      findingId: 'finding-ok-1',
      chainId: 'obs-confirmed',
      terminalVulnClass: 'cross_tenant_secret_read',
      hopCount: 2,
      replayMode: 'fresh_clean_replay',
      confirmed: true,
      attackerProvenanceValid: true,
    },
  ]

  const gt = makeGroundTruth(SPECS)
  const oracleExport = oracle.export()
  const card = gradeRun({
    groundTruth: gt,
    findings: [{ id: 'finding-ok-1', chainId: 'obs-confirmed', status: 'confirmed' }],
    compositeReceipts,
    oracleEvents: [
      ...oracleExport.events.hops.map((h) => ({ eventKind: 'hop', ...h })),
      ...oracleExport.events.edges.map((e) => ({ eventKind: 'edge', ...e })),
      ...oracleExport.events.terminals.map((t) => ({ eventKind: 'terminal', ...t })),
    ],
    oracleExport,
    mode: 'grey-box',
  })

  // Verify scorecard JSON serialization AND benchmark-multihop `evaluateTwoSideConfirmation` pass-through.
  const serializedCard = JSON.parse(renderScorecard(card, 'json')) as ProductScorecard
  const twoSide = evaluateTwoSideConfirmation(serializedCard.chains, compositeReceipts)
  const serializedVerdicts = JSON.parse(JSON.stringify(twoSide.verdicts)) as ProductScorecard['chains']

  for (const chains of [card.chains, serializedCard.chains, serializedVerdicts]) {
    const byId = new Map(chains.map((c) => [c.chainId, c]))

    // Shortcut at hop: names exact disallowed persona 'owner_a' and lists missing hops
    const shortcutHop = byId.get('obs-shortcut-hop')!
    assert.equal(shortcutHop.dropReason, 'persona_shortcut_rejected')
    assert.equal(shortcutHop.forbiddenShortcutViolation, true)
    assert.equal(shortcutHop.maxHopReached, 1)
    assert.equal(shortcutHop.failureReason, "hop h2 executed by disallowed persona 'owner_a'")
    assert.deepEqual(shortcutHop.missingHopIds, ['h2', 'h3'])

    // Shortcut at terminal: names exact disallowed persona 'admin_bot' and has no missing hops
    const shortcutTerminal = byId.get('obs-shortcut-terminal')!
    assert.equal(shortcutTerminal.dropReason, 'persona_shortcut_rejected')
    assert.equal(shortcutTerminal.forbiddenShortcutViolation, true)
    assert.equal(shortcutTerminal.maxHopReached, 2)
    assert.equal(shortcutTerminal.failureReason, "terminal executed by disallowed persona 'admin_bot'")
    assert.deepEqual(shortcutTerminal.missingHopIds, [])

    // Edge binding mismatch: names exact value_binding error and unreached hops
    const edgeValue = byId.get('obs-edge-value')!
    assert.equal(edgeValue.dropReason, 'edge_binding_rejected')
    assert.equal(edgeValue.maxHopReached, 1)
    assert.equal(edgeValue.failureReason, 'value_binding mismatch h1 -> h2')
    assert.deepEqual(edgeValue.missingHopIds, ['h2', 'h3'])

    // State transition binding without control: names exact ablation control error
    const edgeControl = byId.get('obs-edge-control')!
    assert.equal(edgeControl.dropReason, 'edge_binding_rejected')
    assert.equal(edgeControl.maxHopReached, 1)
    assert.equal(edgeControl.failureReason, 'state_transition_binding lacks clean ablation control h1 -> h2')
    assert.deepEqual(edgeControl.missingHopIds, ['h2', 'h3'])

    // Partial hop: names exact missing hop and lists all unreached hops
    const partialHop = byId.get('obs-partial-hop')!
    assert.equal(partialHop.dropReason, 'pivot_not_discovered')
    assert.equal(partialHop.maxHopReached, 1)
    assert.equal(partialHop.failureReason, 'hop h2 (api:api.p2) not observed in order')
    assert.deepEqual(partialHop.missingHopIds, ['h2', 'h3'])

    // Two-side confirmed chain: failureReason is null (never leaks ChainOracle's internal receipt note)
    const confirmed = byId.get('obs-confirmed')!
    assert.equal(confirmed.twoSideConfirmed, true)
    assert.equal(confirmed.dropReason, null)
    assert.equal(confirmed.failureReason, null)
    assert.deepEqual(confirmed.missingHopIds, [])
  }

  // Existing scoring behavior is preserved 100%
  assert.equal(card.chainsTotal, 6)
  assert.equal(card.chainsOracleObserved, 1)
  assert.equal(card.chainsCompositeConfirmed, 1)
  assert.equal(card.chainsConfirmed, 1)
  assert.equal(card.recall, 1 / 6)
  assert.equal(card.precision, 1)
})

test('gradeRun preserves missingHopIds fallback when oracleExport is omitted and surfaces receipt failure when oracleObserved lacks composite receipt', () => {
  const partialSpec = SPECS.find((s) => s.id === 'obs-partial-hop')!
  const confirmedSpec = SPECS.find((s) => s.id === 'obs-confirmed')!

  // Part A: oracleExport omitted (events-only fallback)
  const gtFallback = makeGroundTruth([partialSpec])
  const cardFallback = gradeRun({
    groundTruth: gtFallback,
    findings: [],
    compositeReceipts: [],
    oracleEvents: [{ eventKind: 'hop', seq: 1, chainId: 'obs-partial-hop', hopId: 'h1' }],
    mode: 'grey-box',
  })
  assert.equal(cardFallback.chains.length, 1)
  assert.equal(cardFallback.chains[0]!.dropReason, 'pivot_not_discovered')
  assert.equal(cardFallback.chains[0]!.failureReason, null)
  assert.deepEqual(cardFallback.chains[0]!.missingHopIds, ['h2', 'h3'])

  // Part B: oracleObserved=true without a matching composite receipt
  let tick = 2_000
  const oracle = createChainOracle({
    runId: 'run-obs-1a-oracle-only',
    specs: [confirmedSpec],
    clock: () => {
      tick += 10
      return tick
    },
  })
  const d1 = sha256('oo-h1')
  oracle.recordHop({
    chainId: 'obs-confirmed',
    hopId: 'h1',
    service: 'api',
    routeKey: 'api.ok1',
    actor: 'member_a',
    artifactDigest: d1,
  })
  oracle.recordHop({
    chainId: 'obs-confirmed',
    hopId: 'h2',
    service: 'api',
    routeKey: 'api.ok2',
    actor: 'member_a',
    artifactDigest: sha256('oo-h2'),
  })
  oracle.recordEdge({
    chainId: 'obs-confirmed',
    fromHopId: 'h1',
    toHopId: 'h2',
    kind: 'value_binding',
    fromArtifactDigest: d1,
    toConsumedDigest: d1,
  })
  oracle.recordTerminal({
    chainId: 'obs-confirmed',
    service: 'api',
    routeKey: 'api.ok2',
    kind: 'cross_tenant_secret_read',
    actor: 'member_a',
  })

  const oracleOnlyCard = gradeRun({
    groundTruth: makeGroundTruth([confirmedSpec]),
    findings: [],
    compositeReceipts: [],
    oracleEvents: [],
    oracleExport: oracle.export(),
    mode: 'grey-box',
  })
  assert.equal(oracleOnlyCard.chains[0]!.oracleObserved, true)
  assert.equal(oracleOnlyCard.chains[0]!.twoSideConfirmed, false)
  assert.equal(oracleOnlyCard.chains[0]!.dropReason, 'edge_binding_rejected')
  assert.equal(oracleOnlyCard.chains[0]!.failureReason, 'receipt rejected: no composite receipt')
  assert.deepEqual(oracleOnlyCard.chains[0]!.missingHopIds, [])
})
