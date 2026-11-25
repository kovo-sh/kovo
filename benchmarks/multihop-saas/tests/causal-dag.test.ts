// ChainOracle v2 contract tests: all four typed edge bindings, ordering, persona provenance,
// receipt tampering, two-side confirmation, hop funnel and strict twin/hardened grading.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createChainOracle } from '../lib/chain-oracle.ts'
import type { ChainOracle } from '../lib/chain-oracle.ts'
import { gradeRun } from '../lib/grader.ts'
import type { ChainSpec, CompositeProofReceipt, ExpectedChain, GroundTruth, OracleExport } from '../lib/types.ts'

const SPEC: ChainSpec = {
  id: 'T-C1',
  title: 'synthetic five hop lineage',
  vulnClass: 'cross_tenant_export',
  hops: [
    { hopId: 'h1', service: 'edge', routeKey: 'r.h1', actor: 'member_a' },
    { hopId: 'h2', service: 'api', routeKey: 'r.h2', actor: 'member_a', edgeFromPrevious: 'value_binding' },
    { hopId: 'h3', service: 'api', routeKey: 'r.h3', actor: 'member_a', edgeFromPrevious: 'derived_crypto_binding' },
    { hopId: 'h4', service: 'worker', routeKey: 'r.h4', actor: 'member_a', edgeFromPrevious: 'state_transition_binding' },
    { hopId: 'h5', service: 'edge', routeKey: 'r.h5', actor: 'member_a', edgeFromPrevious: 'async_pivot_binding' },
  ],
  terminal: { service: 'edge', routeKey: 'r.final', kind: 'cross_tenant_export' },
  attackerPersonaSet: ['member_a', 'member_b'],
  forbiddenShortcutPersonas: ['owner_a', 'admin_bot'],
}

function oracle(): ChainOracle {
  return createChainOracle({ runId: 'run-test', specs: [SPEC], key: Buffer.alloc(32, 7) })
}

interface RecordOptions {
  h1Actor?: ChainSpec['hops'][number]['actor']
  h2Ts?: number
  withControl?: boolean
  asyncRunId?: string
  terminalActor?: ChainSpec['hops'][number]['actor']
}

function recordLineage(chain: ChainOracle, options: RecordOptions = {}): void {
  const base = 1000
  chain.recordHop({
    chainId: 'T-C1', hopId: 'h1', service: 'edge', routeKey: 'r.h1',
    actor: options.h1Actor ?? 'member_a', artifactDigest: 'a1', entityId: 'ent', ts: base,
  })
  chain.recordHop({
    chainId: 'T-C1', hopId: 'h2', service: 'api', routeKey: 'r.h2',
    actor: 'member_a', artifactDigest: 'a2', entityId: 'ent', ts: options.h2Ts ?? base + 10,
  })
  chain.recordEdge({
    chainId: 'T-C1', fromHopId: 'h1', toHopId: 'h2', kind: 'value_binding',
    fromArtifactDigest: 'a1', toConsumedDigest: 'a1', ts: base + 10,
  })
  chain.recordHop({
    chainId: 'T-C1', hopId: 'h3', service: 'api', routeKey: 'r.h3',
    actor: 'member_a', artifactDigest: 'a3', entityId: 'ent', ts: base + 20,
  })
  chain.recordEdge({
    chainId: 'T-C1', fromHopId: 'h2', toHopId: 'h3', kind: 'derived_crypto_binding',
    fromArtifactDigest: 'a2', toConsumedDigest: '', derivedFromDigest: 'a2', ts: base + 20,
  })
  chain.recordHop({
    chainId: 'T-C1', hopId: 'h4', service: 'worker', routeKey: 'r.h4',
    actor: 'member_a', artifactDigest: 'a4', entityId: 'ent', ts: base + 30,
  })
  chain.recordEdge({
    chainId: 'T-C1', fromHopId: 'h3', toHopId: 'h4', kind: 'state_transition_binding',
    fromArtifactDigest: 'a3', toConsumedDigest: 'a3', entityId: 'ent', ts: base + 30,
  })
  if (options.withControl !== false) {
    chain.recordControl({
      chainId: 'T-C1', fromHopId: 'h3', toHopId: 'h4', entityId: 'ent',
      result: 'failed_without_predecessor', ts: base + 30,
    })
  }
  chain.recordHop({
    chainId: 'T-C1', hopId: 'h5', service: 'edge', routeKey: 'r.h5',
    actor: 'member_a', artifactDigest: 'a5', entityId: 'ent', ts: base + 40,
  })
  chain.recordEdge({
    chainId: 'T-C1', fromHopId: 'h4', toHopId: 'h5', kind: 'async_pivot_binding',
    fromArtifactDigest: 'a4', toConsumedDigest: 'a4', runId: options.asyncRunId ?? 'run-test',
    pollObserved: true, ts: base + 40,
  })
  chain.recordTerminal({
    chainId: 'T-C1', service: 'edge', routeKey: 'r.final', kind: 'cross_tenant_export',
    actor: options.terminalActor ?? 'member_a', entityId: 'ent', ts: base + 50,
  })
}

test('all four typed causal bindings verify and mint a signed receipt', () => {
  const chain = oracle()
  recordLineage(chain)
  const before = chain.evaluate('T-C1')
  assert.equal(before.completed, true)
  assert.equal(before.confirmed, false)
  assert.equal(before.dropReason, 'replay_failed')

  const receipt = chain.mintReceipt('T-C1')
  assert.equal(chain.verifyReceipt(receipt).ok, true)
  assert.deepEqual(receipt.causalEdges.map((edge) => edge.kind), [
    'value_binding', 'derived_crypto_binding', 'state_transition_binding', 'async_pivot_binding',
  ])
  assert.equal(receipt.replayMode, 'fresh_clean_replay')
  const after = chain.evaluate('T-C1')
  assert.equal(after.confirmed, true)
  assert.equal(after.receiptVerified, true)
  assert.equal(chain.confirmedChains().length, 1)
})

test('out-of-order hop timestamps are rejected even when insertion order is correct', () => {
  const chain = oracle()
  recordLineage(chain, { h2Ts: 900 })
  const evaluation = chain.evaluate('T-C1')
  assert.equal(evaluation.completed, false)
  assert.equal(evaluation.hopsObserved, 1)
  assert.equal(evaluation.dropReason, 'pivot_not_discovered')
  assert.throws(() => chain.mintReceipt('T-C1'), /not observed in order/)
})

test('persona shortcutting is rejected at the first hop and at the terminal', () => {
  const first = oracle()
  recordLineage(first, { h1Actor: 'owner_a' })
  const start = first.evaluate('T-C1')
  assert.equal(start.completed, false)
  assert.equal(start.dropReason, 'persona_shortcut_rejected')

  const last = oracle()
  recordLineage(last, { terminalActor: 'admin_bot' })
  const terminal = last.evaluate('T-C1')
  assert.equal(terminal.completed, false)
  assert.equal(terminal.dropReason, 'persona_shortcut_rejected')

  const forged = oracle()
  recordLineage(forged)
  const receipt = forged.mintReceipt('T-C1')
  const swapped = { ...receipt, hops: receipt.hops.map((hop, index) => index === 0 ? { ...hop, actor: 'owner_a' as const } : hop) }
  assert.equal(forged.verifyReceipt(swapped).ok, false)
})

test('state transition needs a clean ablation control; async pivot needs run scope', () => {
  const noControl = oracle()
  recordLineage(noControl, { withControl: false })
  const evalNoControl = noControl.evaluate('T-C1')
  assert.equal(evalNoControl.completed, false)
  assert.equal(evalNoControl.dropReason, 'edge_binding_rejected')
  assert.match(evalNoControl.failureReason ?? '', /ablation control/)

  const wrongRun = oracle()
  recordLineage(wrongRun, { asyncRunId: 'another-run' })
  const evalWrongRun = wrongRun.evaluate('T-C1')
  assert.equal(evalWrongRun.completed, false)
  assert.equal(evalWrongRun.dropReason, 'edge_binding_rejected')
  assert.match(evalWrongRun.failureReason ?? '', /poll correlation/)
})

test('receipt tampering and non-Mode-A replay are rejected', () => {
  const chain = oracle()
  recordLineage(chain)
  const receipt = chain.mintReceipt('T-C1')

  const badSignature: CompositeProofReceipt = {
    ...receipt,
    signature: `${receipt.signature.slice(0, -2)}00`,
  }
  assert.equal(chain.verifyReceipt(badSignature).ok, false)
  assert.match(chain.verifyReceipt(badSignature).reason, /signature mismatch/)

  const badHop: CompositeProofReceipt = {
    ...receipt,
    hops: receipt.hops.map((hop, index) => index === 2 ? { ...hop, routeKey: 'r.elsewhere' } : hop),
  }
  assert.equal(chain.verifyReceipt(badHop).ok, false)
  assert.match(chain.verifyReceipt(badHop).reason, /does not match chain spec/)

  const oneShot: CompositeProofReceipt = { ...receipt, replayMode: 'one_shot_transcript' }
  assert.equal(chain.verifyReceipt(oneShot).ok, false)
  assert.match(chain.verifyReceipt(oneShot).reason, /replay_mode_not_allowed/)
})

function truth(overrides: Partial<GroundTruth> = {}): GroundTruth {
  return {
    app: 'paygrid', seed: 1, seedSet: 'dev', labMode: 'vulnerable',
    expectedChains: [], twinDecoys: [], topology: [], personas: [],
    ...overrides,
  }
}

function emptyOracle(): OracleExport {
  const chain = oracle()
  return chain.export()
}

test('hardened and partial-twin findings are strict false positives', () => {
  const finding = { chainId: 'T-C1', terminalVulnClass: 'cross_tenant_export' }
  const twin = gradeRun({
    groundTruth: truth({
      twinId: 'T-D1',
      twinDecoys: [{
        chainId: 'T-C1', benignHopIds: ['h1', 'h2'], enforcedAtHopId: 'h3', note: 'benign early hops',
      }],
    }),
    findings: [finding],
    oracle: emptyOracle(),
  })
  assert.equal(twin.tp, 0)
  assert.equal(twin.fp, 1)
  assert.equal(twin.strictDecoyFps, 1)
  assert.equal(twin.fpByCategory.decoy_twin, 1)
  assert.equal(twin.precision, 0)
  assert.equal(twin.gate.pass, false)

  const hardened = gradeRun({
    groundTruth: truth({ labMode: 'hardened' }),
    findings: [finding],
    oracle: emptyOracle(),
  })
  assert.equal(hardened.fpByCategory.hardened_counterpart, 1)
  assert.equal(hardened.precision, 0)
})

test('two-side grading: starred causal DAG without a receipt is not a true positive', () => {
  const chain = oracle()
  recordLineage(chain)
  const expected: ExpectedChain[] = [{
    chainId: 'T-C1', vulnClass: 'cross_tenant_export',
    hopIds: ['h1', 'h2', 'h3', 'h4', 'h5'],
    edgeKinds: ['value_binding', 'derived_crypto_binding', 'state_transition_binding', 'async_pivot_binding'],
    terminalKind: 'cross_tenant_export',
  }]
  const finding = { chainId: 'T-C1', terminalVulnClass: 'cross_tenant_export' }

  const unconfirmed = gradeRun({
    groundTruth: truth({ expectedChains: expected }),
    findings: [finding],
    oracle: chain.export(),
  })
  assert.equal(unconfirmed.tp, 0)
  assert.equal(unconfirmed.fpByCategory.unconfirmed, 1)
  assert.equal(unconfirmed.precision, 0)
  assert.equal(unconfirmed.hopFunnel.finalOracle, 1)
  assert.equal(unconfirmed.hopFunnel.receiptConfirmed, 0)

  const receipt = chain.mintReceipt('T-C1')
  const confirmed = gradeRun({
    groundTruth: truth({ expectedChains: expected }),
    findings: [{ ...finding, receipt }],
    oracle: chain.export(),
  })
  assert.equal(confirmed.tp, 1)
  assert.equal(confirmed.fp, 0)
  assert.equal(confirmed.fn, 0)
  assert.equal(confirmed.precision, 1)
  assert.equal(confirmed.recall, 1)
  assert.equal(confirmed.gate.pass, true)
  assert.deepEqual(confirmed.hopFunnel, {
    h1: 1, h2: 1, h3: 1, h4plus: 1, finalOracle: 1, receiptConfirmed: 1,
  })
})

test('missing expected chains are reported as false negatives with drop reasons', () => {
  const card = gradeRun({
    groundTruth: truth({
      expectedChains: [
        {
          chainId: 'T-C1', vulnClass: 'cross_tenant_export', hopIds: ['h1'],
          edgeKinds: [], terminalKind: 'cross_tenant_export',
        },
        {
          chainId: 'T-C2', vulnClass: 'ledger_overcredit', hopIds: ['h1'],
          edgeKinds: [], terminalKind: 'ledger_overcredit',
        },
      ],
    }),
    findings: [],
    oracle: emptyOracle(),
  })
  assert.equal(card.tp, 0)
  assert.equal(card.fn, 2)
  assert.deepEqual(card.missedChainIds.sort(), ['T-C1', 'T-C2'])
  assert.equal(card.precision, 1)
  assert.equal(card.recall, 0)
  assert.equal(card.dropReasons.capability_not_extracted, 1)
})
