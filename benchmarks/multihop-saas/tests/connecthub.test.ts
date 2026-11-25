// Live connecthub loopback suites: vulnerable 4/4, hardened silence, partial-twin silence, leak
// scan, lifecycle hooks, run tagging, configurable async latency and salted held-out seeds.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join } from 'node:path'
import { ANTI_HEURISTIC_FLOOR_MAX, gradeRun } from '../lib/grader.ts'
import { scanTreeForLeakage } from '../lib/materialize.ts'
import { causalEdgeKinds } from '../lib/types.ts'
import type { CausalEdgeKind, Finding, TerminalImpactKind } from '../lib/types.ts'
import type { StartedConnecthub } from '../apps/connecthub/index.ts'
import {
  CONNECTHUB_META, describeApp, startConnecthub,
} from '../apps/connecthub/index.ts'
import { createSolverContext, runReferenceSolvers } from '../apps/connecthub/solvers/index.ts'

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function grade(lab: StartedConnecthub, findings: Finding[]) {
  return gradeRun({ groundTruth: lab.groundTruth, findings, oracle: lab.export() })
}

test('connecthub is sealed metadata with four chains and three partial twins', () => {
  assert.equal(CONNECTHUB_META.sealed, true)
  assert.equal(CONNECTHUB_META.split, 'sealed')
  const info = describeApp()
  assert.equal(info.app, 'connecthub')
  assert.equal(info.chains, 4)
  assert.equal(info.twins, 3)
  assert.equal(info.services, 5)
  assert.equal(info.sealed, true)
})

test('vulnerable connecthub: 4/4 reference runners pass ChainOracle v2 + composite receipt', async () => {
  const lab = await startConnecthub({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    assert.equal(Object.keys(lab.plan.personas).length, 7)
    assert.equal(Object.keys(lab.plan.tenants).length, 3)
    const findings = await runReferenceSolvers(lab)
    assert.deepEqual(
      findings.map((finding) => finding.chainId).sort(),
      ['CH-C1', 'CH-C2', 'CH-C3', 'CH-C4'],
    )

    const exported = lab.export()
    assert.equal(exported.confirmed.length, 4)
    for (const chain of exported.confirmed) {
      assert.equal(chain.receiptVerified, true)
      assert.equal(lab.oracle.verifyReceipt(chain.receipt).ok, true)
    }
    for (const evaluation of exported.evaluations) {
      assert.equal(evaluation.completed, true, evaluation.failureReason ?? 'incomplete')
      assert.equal(evaluation.confirmed, true, evaluation.failureReason ?? 'incomplete')
      assert.equal(evaluation.terminalObserved, true)
      assert.equal(evaluation.receiptVerified, true)
    }

    const kinds = new Set<CausalEdgeKind>(exported.events.edges.map((edge) => edge.kind))
    assert.deepEqual([...kinds].sort(), [...causalEdgeKinds].sort())
    assert.equal(exported.events.terminals.length, 4)

    const card = grade(lab, findings)
    assert.equal(card.tp, 4)
    assert.equal(card.fp, 0)
    assert.equal(card.fn, 0)
    assert.equal(card.precision, 1)
    assert.equal(card.recall, 1)
    assert.equal(card.strictDecoyFps, 0)
    assert.equal(card.gate.pass, true)
    assert.deepEqual(card.hopFunnel, { h1: 4, h2: 4, h3: 4, h4plus: 4, finalOracle: 4, receiptConfirmed: 4 })

    const origins = Object.values(lab.origins)
    assert.equal(origins.length, 5)
    assert.equal(new Set(origins).size, 5)
    for (const origin of origins) assert.equal(new URL(origin).hostname, '127.0.0.1')
  } finally {
    await lab.stop()
  }
})

test('hardened connecthub: all four runners emit zero oracle events', async () => {
  const lab = await startConnecthub({ seed: 42, mode: 'hardened', asyncLatencyMs: 5 })
  try {
    const findings = await runReferenceSolvers(lab)
    assert.deepEqual(findings, [])
    const exported = lab.export()
    assert.equal(exported.events.hops.length, 0)
    assert.equal(exported.events.edges.length, 0)
    assert.equal(exported.events.controls.length, 0)
    assert.equal(exported.events.terminals.length, 0)
    assert.equal(exported.confirmed.length, 0)
    for (const evaluation of exported.evaluations) {
      assert.equal(evaluation.hopsObserved, 0)
      assert.equal(evaluation.confirmed, false)
    }

    const clean = grade(lab, findings)
    assert.equal(clean.precision, 1)
    assert.equal(clean.fp, 0)
    assert.equal(clean.gate.pass, true)

    const fabricated: Finding[] = [
      { chainId: 'CH-C1', terminalVulnClass: 'delegated_billing_rebate' },
      { chainId: 'CH-C4', terminalVulnClass: 'cross_tenant_partner_export' },
    ]
    const poisoned = grade(lab, fabricated)
    assert.equal(poisoned.fpByCategory.hardened_counterpart, 2)
    assert.equal(poisoned.precision, 0)
    assert.equal(poisoned.gate.pass, false)
  } finally {
    await lab.stop()
  }
})

test('partial-hop twins: real early hops, zero terminal events, strict decoy FP grading', async () => {
  const twins: Array<{ id: string; chain: string; terminal: TerminalImpactKind }> = [
    { id: 'CH-D1', chain: 'CH-C1', terminal: 'delegated_billing_rebate' },
    { id: 'CH-D2', chain: 'CH-C2', terminal: 'cross_tenant_secret_read' },
    { id: 'CH-D3', chain: 'CH-C3', terminal: 'split_refund_ledger_break' },
  ]
  for (const twin of twins) {
    const lab = await startConnecthub({
      seed: 42, mode: 'vulnerable', twin: twin.id, asyncLatencyMs: 5,
    })
    try {
      const findings = await runReferenceSolvers(lab, [twin.chain])
      const exported = lab.export()
      const evaluation = lab.oracle.evaluate(twin.chain)
      assert.deepEqual(findings, [], twin.id)
      assert.equal(exported.events.terminals.length, 0, twin.id)
      assert.equal(evaluation.terminalObserved, false, twin.id)
      assert.equal(evaluation.confirmed, false, twin.id)
      assert.ok(evaluation.hopsObserved >= 2, `${twin.id} should exercise at least hops 1-2`)
      assert.ok(exported.events.hops.length >= 2, twin.id)

      const clean = grade(lab, findings)
      assert.equal(clean.fp, 0, twin.id)
      assert.equal(clean.precision, 1, twin.id)

      const decoy: Finding[] = [{
        chainId: twin.chain,
        terminalVulnClass: twin.terminal,
        hopIds: [evaluation.missingHopIds[0] ?? ''],
      }]
      const poisoned = grade(lab, decoy)
      assert.equal(poisoned.fpByCategory.decoy_twin, 1, twin.id)
      assert.equal(poisoned.strictDecoyFps, 1, twin.id)
      assert.equal(poisoned.precision, 0, twin.id)
    } finally {
      await lab.stop()
    }
  }
})

test('materialized white-box tree is leakage-scan clean; briefings expose mode-scoped views', async () => {
  const lab = await startConnecthub({ seed: 7, mode: 'vulnerable', asyncLatencyMs: 1 })
  try {
    const root = join(lab.sourceDir, '..', '..', '..')
    assert.deepEqual(scanTreeForLeakage(root), [])

    const black = lab.briefing('black-box')
    assert.equal(black.personas.length, 3)
    assert.equal(black.apiReference, undefined)
    assert.equal(black.sourceDir, undefined)
    assert.ok(black.entryOrigins.portal)
    assert.equal(black.entryOrigins.api, undefined)

    const grey = lab.briefing('grey-box')
    assert.equal(grey.personas.length, 6)
    assert.ok((grey.apiReference?.length ?? 0) >= 80)
    assert.ok(grey.services?.some((service) => service.id === 'webhook-relay' && service.internal))
    assert.ok(grey.services?.some((service) => service.id === 'billing.internal' && service.internal))
    assert.ok(grey.internalServiceNames?.includes('billing.internal'))
    assert.equal(grey.sourceDir, undefined)
    assert.ok(!grey.personas.some((persona) => persona.id === 'admin_bot'))

    const white = lab.briefing('white-box')
    assert.equal(white.sourceDir, lab.sourceDir)
    assert.ok((white.apiReference?.length ?? 0) >= 80)
  } finally {
    await lab.stop()
  }
})

test('renewable lifecycle hooks, X-Guardian-Run-Id tagging and fast-lab async latency', async () => {
  const lab = await startConnecthub({ seed: 9, mode: 'vulnerable', asyncLatencyMs: 40 })
  try {
    const ctx = createSolverContext(lab)
    const owner = await ctx.login('owner_a')
    const prefix = lab.plan.routePrefix

    const pat = await ctx.http('oauth', '/pats', {
      method: 'POST', token: owner, body: { scopes: ['read', 'billing.read'] },
    })
    assert.equal(pat.status, 201)
    const patId = pat.json<{ id: string }>().id
    assert.equal((await ctx.http('oauth', `/pats/${patId}/revoke`, { method: 'POST', token: owner })).status, 200)

    const webhook = await ctx.http('api', `${prefix}/webhooks`, {
      method: 'POST', token: owner,
      body: { url: 'https://hooks.partner.example/inbound', events: ['app.updated'] },
    })
    assert.equal(webhook.status, 201)
    const registration = webhook.json<{ webhookId: string; deliveryId: string }>()

    const immediate = await ctx.http('webhook-relay', `/deliveries/${registration.deliveryId}`)
    assert.equal(immediate.json<{ delivery: { status: string } }>().delivery.status, 'queued')
    await sleep(80)
    const ready = await ctx.http('webhook-relay', `/deliveries/${registration.deliveryId}`)
    const delivery = ready.json<{
      delivery: { status: string; tenantId: string; signature: string }
    }>().delivery
    assert.equal(delivery.status, 'ready')
    assert.equal(delivery.tenantId, 'org_a')
    assert.ok(delivery.signature.length >= 32)

    const second = await ctx.http('api', `${prefix}/webhooks`, {
      method: 'POST', token: owner,
      body: { url: 'https://hooks.partner.example/second', events: ['billing.updated'] },
    })
    const secondId = second.json<{ deliveryId: string }>().deliveryId
    const cancelled = await ctx.http('webhook-relay', `/jobs/${secondId}/cancel`, { method: 'POST' })
    assert.equal(cancelled.status, 200)
    const afterCancel = await ctx.http('webhook-relay', `/deliveries/${secondId}`)
    assert.equal(afterCancel.json<{ delivery: { status: string } }>().delivery.status, 'cancelled')

    assert.equal(
      (await ctx.http('api', `${prefix}/webhooks/${registration.webhookId}`, {
        method: 'DELETE', token: owner,
      })).status, 200,
    )
    assert.equal((await ctx.http('oauth', '/keys/rotate', { method: 'POST', token: owner })).status, 200)
    assert.equal(
      (await ctx.http('billing.internal', '/keys/rotate', {
        method: 'POST', headers: { 'x-service-token': ctx.serviceToken },
      })).status, 200,
    )
    const reset = await ctx.http('billing.internal', '/reset', {
      method: 'POST', headers: { 'x-service-token': ctx.serviceToken },
    })
    assert.equal(reset.status, 200)
    assert.equal(reset.json<{ reset: boolean }>().reset, true)

    for (const deliveryRow of lab.export().events.hops) {
      assert.equal(typeof deliveryRow.ts, 'number')
    }
  } finally {
    await lab.stop()
  }
})

test('soundness sweep: seeds 1-3 keep 4/4 vulnerable recall and hardened silence', async () => {
  for (const seed of [1, 2, 3]) {
    const vulnerable = await startConnecthub({ seed, mode: 'vulnerable', asyncLatencyMs: 3 })
    try {
      const findings = await runReferenceSolvers(vulnerable)
      const card = grade(vulnerable, findings)
      assert.equal(findings.length, 4, `seed ${seed}`)
      assert.equal(card.tp, 4, `seed ${seed}`)
      assert.equal(card.fp, 0, `seed ${seed}`)
      assert.equal(card.gate.pass, true, `seed ${seed}`)
    } finally {
      await vulnerable.stop()
    }

    const hardened = await startConnecthub({ seed, mode: 'hardened', asyncLatencyMs: 3 })
    try {
      const findings = await runReferenceSolvers(hardened)
      const events = hardened.export().events
      const total = events.hops.length + events.edges.length + events.controls.length + events.terminals.length
      assert.deepEqual(findings, [], `seed ${seed}`)
      assert.equal(total, 0, `seed ${seed}`)
    } finally {
      await hardened.stop()
    }
  }
})

test('salted held-out seeds run through the same lab', async () => {
  const previous = process.env.GUARDIAN_RB_HELDOUT_SALT
  process.env.GUARDIAN_RB_HELDOUT_SALT = 'unit-test-held-out-salt'
  const lab = await startConnecthub({ seed: 1_000_042, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    assert.equal(lab.seedSet, 'held-out')
    const findings = await runReferenceSolvers(lab)
    assert.equal(findings.length, 4)
    assert.equal(grade(lab, findings).gate.pass, true)
  } finally {
    await lab.stop()
    if (previous === undefined) delete process.env.GUARDIAN_RB_HELDOUT_SALT
    else process.env.GUARDIAN_RB_HELDOUT_SALT = previous
  }
})

test('anti-heuristic floor: an empty deterministic run scores <= 5% recall', async () => {
  const lab = await startConnecthub({ seed: 11, mode: 'vulnerable', asyncLatencyMs: 1 })
  try {
    const card = grade(lab, [])
    assert.equal(card.recall, 0)
    assert.equal(card.precision, 1)
    assert.ok(card.recall <= ANTI_HEURISTIC_FLOOR_MAX)
    assert.equal(ANTI_HEURISTIC_FLOOR_MAX, 0.05)
  } finally {
    await lab.stop()
  }
})
