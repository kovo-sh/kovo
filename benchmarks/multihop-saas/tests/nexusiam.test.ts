// Live nexusiam loopback suites: vulnerable 4/4, hardened silence, partial-twin silence, leak scan,
// lifecycle hooks, run tagging and configurable async latency.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync } from 'node:fs'
import { join } from 'node:path'
import { gradeRun, ANTI_HEURISTIC_FLOOR_MAX } from '../lib/grader.ts'
import { scanTreeForLeakage } from '../lib/materialize.ts'
import { causalEdgeKinds } from '../lib/types.ts'
import type { CausalEdgeKind, Finding } from '../lib/types.ts'
import { startNexusiam } from '../apps/nexusiam/index.ts'
import { runNexusiamSolvers, createSolverContext } from '../apps/nexusiam/solvers/index.ts'

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function grade(lab: Awaited<ReturnType<typeof startNexusiam>>, findings: Finding[]) {
  return gradeRun({ groundTruth: lab.groundTruth, findings, oracle: lab.export() })
}

test('vulnerable nexusiam: 4/4 reference solvers pass ChainOracle v2 + composite receipt', async () => {
  const lab = await startNexusiam({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const findings = await runNexusiamSolvers(lab)
    assert.deepEqual(findings.map((finding) => finding.chainId).sort(), ['NX-C1', 'NX-C2', 'NX-C3', 'NX-C4'])

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

    assert.equal(Object.keys(lab.plan.personas).length, 7)
    assert.equal(Object.keys(lab.plan.tenants).length, 3)
    assert.equal(lab.plan.personas.admin_bot.bot, true)
    assert.deepEqual(lab.plan.personas.dual_member.rolesByTenant, { org_a: 'admin', org_b: 'viewer' })
  } finally {
    await lab.stop()
  }
})

test('hardened nexusiam: all four solvers emit zero oracle events', async () => {
  const lab = await startNexusiam({ seed: 42, mode: 'hardened', asyncLatencyMs: 5 })
  try {
    const findings = await runNexusiamSolvers(lab)
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

    const fabricated: Finding[] = [{ chainId: 'NX-C1', terminalVulnClass: 'privilege_escalation' }]
    const poisoned = grade(lab, fabricated)
    assert.equal(poisoned.fpByCategory.hardened_counterpart, 1)
    assert.equal(poisoned.precision, 0)
    assert.equal(poisoned.gate.pass, false)
  } finally {
    await lab.stop()
  }
})

test('partial-hop twins: real early hops, zero terminal oracle events, strict decoy FP grading', async () => {
  const twins = [
    { id: 'NX-D1', chain: 'NX-C1' },
    { id: 'NX-D2', chain: 'NX-C2' },
    { id: 'NX-D3', chain: 'NX-C3' },
  ]
  for (const twin of twins) {
    const lab = await startNexusiam({ seed: 42, mode: 'vulnerable', twin: twin.id, asyncLatencyMs: 5 })
    try {
      const findings = await runNexusiamSolvers(lab, [twin.chain])
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
        terminalVulnClass: 'cross_tenant_document_read',
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
  const lab = await startNexusiam({ seed: 7, mode: 'vulnerable', asyncLatencyMs: 1 })
  try {
    assert.deepEqual(scanTreeForLeakage(lab.sourceRoot), [])
    const snapshot = readdirSync(lab.sourceDir)
    assert.ok(snapshot.includes('server.ts'))
    assert.ok(!snapshot.some((name) => /truth|solver|decoy|proxy|host/i.test(name)))

    const black = lab.briefing('black-box')
    assert.equal(black.personas.length, 3)
    assert.equal(black.apiReference, undefined)
    assert.equal(black.sourceDir, undefined)
    assert.ok((black.entryOrigins as Record<string, string>)['cdn'])

    const grey = lab.briefing('grey-box')
    assert.equal(grey.personas.length, 6)
    assert.ok((grey.apiReference?.length ?? 0) >= 50)
    assert.ok(grey.services?.some((service) => (service.id as string) === 'docs-worker' && service.internal))
    assert.ok((grey.internalServiceNames ?? []).map(String).includes('docs-worker'))
    assert.equal(grey.sourceDir, undefined)
    assert.ok(!grey.personas.some((persona) => persona.id === 'admin_bot'))

    const white = lab.briefing('white-box')
    assert.equal(white.sourceDir, lab.sourceDir)
    assert.ok((white.apiReference?.length ?? 0) >= 50)
  } finally {
    await lab.stop()
  }
})

test('renewable lifecycle hooks, X-Guardian-Run-Id tagging and fast-lab async latency', async () => {
  const lab = await startNexusiam({ seed: 9, mode: 'vulnerable', asyncLatencyMs: 80 })
  try {
    const ctx = createSolverContext(lab)
    const owner = await ctx.login('owner_a')
    const prefix = lab.plan.routePrefix

    const invite = await ctx.http('idp', '/invites', {
      method: 'POST',
      token: owner,
      body: { tenant: lab.plan.tenants.a.slug, email: 'mh_fake_lifecycle@example.test', role: 'member' },
    })
    assert.equal(invite.status, 201)
    const inviteId = invite.json<{ id: string }>().id
    assert.equal((await ctx.http('idp', `/invites/${inviteId}/revoke`, { method: 'POST', token: owner })).status, 200)

    const pat = await ctx.http('idp', '/pats', { method: 'POST', token: owner, body: { scopes: ['read', 'docs.read'] } })
    assert.equal(pat.status, 201)
    const patId = pat.json<{ id: string }>().id
    assert.equal((await ctx.http('idp', `/pats/${patId}/revoke`, { method: 'POST', token: owner })).status, 200)

    const scim = await ctx.http('api', `${prefix}/scim/tokens`, {
      method: 'POST', token: owner, body: { scopes: ['scim.read', 'scim.write'] },
    })
    assert.equal(scim.status, 201)
    const scimId = scim.json<{ id: string }>().id
    assert.equal((await ctx.http('api', `${prefix}/scim/tokens/${scimId}/revoke`, { method: 'POST', token: owner })).status, 200)

    const created = await ctx.http('docs-worker', '/jobs/export', {
      method: 'POST',
      body: { tenantId: 'org_a', userId: lab.plan.personas.owner_a.userId },
    })
    assert.equal(created.status, 202)
    const jobId = created.json<{ jobId: string }>().jobId

    const immediate = await ctx.http('docs-worker', `/jobs/${jobId}`)
    assert.equal(immediate.json<{ job: { status: string } }>().job.status, 'queued')
    await sleep(130)
    const ready = await ctx.http('docs-worker', `/jobs/${jobId}`)
    const job = ready.json<{ job: { status: string; runId: string } }>().job
    assert.equal(job.status, 'ready')
    assert.equal(job.runId, lab.runId)

    const second = await ctx.http('docs-worker', '/jobs/export', {
      method: 'POST', body: { tenantId: 'org_a', folderName: 'shared' },
    })
    const secondId = second.json<{ jobId: string }>().jobId
    assert.equal((await ctx.http('docs-worker', `/jobs/${secondId}/cancel`, { method: 'POST' })).status, 200)
    const afterCancel = await ctx.http('docs-worker', `/jobs/${secondId}`)
    assert.equal(afterCancel.json<{ job: { status: string } }>().job.status, 'cancelled')
  } finally {
    await lab.stop()
  }
})

test('salted held-out seeds run through the same lab', async () => {
  const previous = process.env.GUARDIAN_RB_HELDOUT_SALT
  process.env.GUARDIAN_RB_HELDOUT_SALT = 'unit-test-held-out-salt'
  const lab = await startNexusiam({ seed: 1_000_042, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    assert.equal(lab.seedSet, 'held-out')
    const findings = await runNexusiamSolvers(lab)
    assert.equal(findings.length, 4)
    assert.equal(grade(lab, findings).gate.pass, true)
  } finally {
    await lab.stop()
    if (previous === undefined) delete process.env.GUARDIAN_RB_HELDOUT_SALT
    else process.env.GUARDIAN_RB_HELDOUT_SALT = previous
  }
})

test('anti-heuristic floor: an empty deterministic run scores <= 5% recall', async () => {
  const lab = await startNexusiam({ seed: 11, mode: 'vulnerable', asyncLatencyMs: 1 })
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
